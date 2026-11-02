"""Reporting Service (РўР— 2.5): security.assessed в†’ РєР°СЂС‚РѕС‡РєР° РёРЅРґРёРєР°С‚РѕСЂРѕРІ (2.5.1)
Рё РїСЂРѕРµРєС‚ РѕС‚РІРµС‚Р° (2.5.2) в†’ report.ready + reply.generated."""
import asyncio
import base64
import logging
import re
from datetime import date, datetime, timezone
from pathlib import Path

from shared.bus import get_event_bus
from shared.config import ORG_NAME, REPORT_DIR
from shared.db import SessionLocal, init_db
from shared.events import ReportReady, ReplyGenerated
from shared.generator.indicator_card import build_indicator_card, report_filename
from shared.generator.response_generator import render_reply_docx
from shared.models import (
    Document, GeneratedResponse, IoC, Report, Threat, Vulnerability,
)
from shared.worker import configure_logging, register_handlers, serve_forever

logger = logging.getLogger("fstec.reporting")

_BDU_TEXT_RE = re.compile(r"BDU[:\s-]*(\d{4})[-\s]*(\d+)", re.I)
_CVE_TEXT_RE = re.compile(r"CVE[-\s]*(\d{4})[-\s]*(\d+)", re.I)


def _source_ids(doc) -> tuple[set[str], set[str]]:
    text = "\n".join(x for x in (doc.all_text, doc.original_text) if x)
    bdu = {f"BDU:{a}-{b}" for a, b in _BDU_TEXT_RE.findall(text)}
    cve = {f"CVE-{a}-{b}" for a, b in _CVE_TEXT_RE.findall(text)}
    return bdu, cve


def _filter_assessed(assessed: list[dict], source_bdu: set[str], source_cve: set[str]) -> list[dict]:
    """Убирает записи, которых нет в исходном письме (NVD/LLM-дубли и лишние BDU)."""
    if not source_bdu and not source_cve:
        return assessed
    out = []
    for v in assessed:
        bdu = str(v.get("bdu_id") or "").strip().upper()
        cve = str(v.get("cve_id") or "").strip().upper()
        if not bdu and not cve:
            out.append(v)
            continue
        if (bdu and bdu in source_bdu) or (cve and cve in source_cve):
            out.append(v)
    return out


def _now():
    return datetime.now(timezone.utc)


async def handle_assessed(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    assessed_vulns = payload.get("vulnerabilities", [])

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip report", doc_id)
            return

        source_bdu, source_cve = _source_ids(doc)
        assessed_vulns = _filter_assessed(assessed_vulns, source_bdu, source_cve)

        ioc = db.query(IoC).filter(IoC.document_id == doc_id).all()
        ips = [i.value for i in ioc if i.ioc_type in ("ip", "ip_cidr")]
        ipv6 = [i.value for i in ioc if i.ioc_type == "ipv6"]
        domains = [i.value for i in ioc if i.ioc_type == "domain"]
        emails = [i.value for i in ioc if i.ioc_type == "email"]

        vulns = [{
            "cve_id": v.get("cve_id", ""),
            "bdu_id": v.get("bdu_id", ""),
            "description": v.get("description", ""),
            "software": v.get("software", ""),
            "severity": v.get("severity", "unknown"),
            "cvss_score": v.get("cvss_score"),
            "cvss_version": v.get("cvss_version", ""),
            "affected_range": v.get("affected_range", ""),
            "fixed_version": v.get("fixed_version", ""),
            "patch_url": v.get("patch_url", ""),
            "current_version": v.get("current_version", ""),
            "target_version": v.get("target_version", ""),
            "recommendation": v.get("recommendation", ""),
            "cmdb_match": v.get("cmdb_match", False),
            "cmdb_error": v.get("cmdb_error", ""),
            "is_applicable": v.get("is_applicable"),
            "source": v.get("source", "manual"),
        } for v in assessed_vulns]

        # 2.5.1 РљР°СЂС‚РѕС‡РєР° РёРЅРґРёРєР°С‚РѕСЂРѕРІ
        card_bytes = build_indicator_card(
            org_name=ORG_NAME,
            source_filename=doc.source_filename,
            document_id=doc.id,
            ips=ips,
            ipv6=ipv6,
            domains=domains,
            emails=emails,
            vulnerabilities=vulns,
            sla=doc.sla,
        )
        fname = report_filename(doc.source_filename)
        report_dir = REPORT_DIR / f"doc_{doc.id}"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / fname
        report_path.write_bytes(card_bytes)

        db.add(Report(document_id=doc.id, report_type="indicator_card",
                      filename=fname, file_path=str(report_path)))
        db.commit()

        # 2.5.2 РџСЂРѕРµРєС‚ РѕС‚РІРµС‚Р° (С€Р°Р±Р»РѕРЅ + Р±РёР±Р»РёРѕС‚РµРєР° РјРµСЂ + LLM-РїРѕРґР±РѕСЂ; fallback вЂ” РґРµС‚РµСЂРјРёРЅРёСЂРѕРІР°РЅРЅС‹Р№)
        threat_rows = (db.query(Threat).filter(Threat.document_id == doc_id)
                       .order_by(Threat.number).all())
        blocks = [{
            "id": t.id, "number": t.number, "threat_type": t.threat_type, "theme": t.theme,
            "group_name": t.group_name, "archive_name": t.archive_name, "exe_name": t.exe_name,
            "malware_type": t.malware_type, "description": t.description,
            "explicit_measures": [m.strip() for m in (t.measures or "").split("\n") if m.strip()],
        } for t in threat_rows]
        from shared.generator.templated_reply import generate_reply_async, persist_candidates
        # Сессия БД переживает await: план и measure library читаются из неё же.
        # Поэтому DB_POOL_SIZE должен быть >= BUS_CONCURRENCY reporting-воркера,
        # иначе обработчики упрутся в очередь пула (см. shared/db.py).
        rep = await generate_reply_async(
            db=db, doc_id=doc.id, letter_type=doc.letter_type, blocks=blocks,
            addr_count=len(domains) + len(ips), active_vulns=[v for v in vulns],
            addresses=sorted({*domains, *ips}),
        )
        if rep["candidates"]:
            for i, c in enumerate(rep["candidates"]):
                rep["candidates"][i]["threat_id"] = (blocks[i]["id"] if i < len(blocks) else None)
            persist_candidates(db, doc.id, rep["candidates"])

        reply_text = rep["text"]
        reply_docx = render_reply_docx(reply_text)
        ans_fname = f"answer_{doc.id}.docx"
        reply_path = report_dir / ans_fname
        reply_path.write_bytes(reply_docx)

        db.add(GeneratedResponse(document_id=doc.id, content=reply_text,
                                 edited_content=base64.b64encode(reply_docx).decode("ascii"),
                                 plan_json=rep["plan_json"]))

        doc.processing_stage = "done"
        doc.status = "completed"
        db.commit()

        card_rel, reply_rel = str(report_path), str(reply_path)

    await get_event_bus().publish("report.ready", str(doc_id), ReportReady(
        document_id=doc_id, report_type="indicator_card", filename=fname,
        file_path=card_rel).model_dump(mode="json"))
    await get_event_bus().publish("reply.generated", str(doc_id), ReplyGenerated(
        document_id=doc_id, filename=ans_fname,
        file_path=reply_rel, text=reply_text).model_dump(mode="json"))
    logger.info("Report + reply generated for doc %s", doc_id)


def main():
    configure_logging()
    from shared.registry import register_service
    register_service("reporting")
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"security.assessed": handle_assessed})
        try:
            await serve_forever(bus, heartbeat_name="reporting")
        finally:
            from llm_service.provider import close_provider_clients
            await close_provider_clients()
    asyncio.run(_run())


if __name__ == "__main__":
    main()