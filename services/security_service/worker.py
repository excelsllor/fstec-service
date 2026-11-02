"""Security Posture Analyzer (РўР— 2.4): document.analyzed в†’ РѕР±РѕРіР°С‰РµРЅРёРµ NVD/BDU + CMDB +
РІРµСЂСЃРёРѕРЅРЅС‹Р№ matching в†’ security.assessed (keep-all; match вЂ” С„Р»Р°Рі). РќРµРґРѕСЃС‚СѓРїРЅРѕСЃС‚СЊ РІРЅРµС€РЅРёС…
Р‘Р” в†’ graceful (raw РІ РїРёСЃСЊРјРµ), РІРЅРµС€РЅРёРµ РѕС€РёР±РєРё РІ external_errors + audit + DLQ (РўР— 4.2)."""
import asyncio
import logging

from sqlalchemy.orm import Session

from shared.bus import KafkaEventBus, get_event_bus
from shared.concurrency import bounded_gather, run_blocking
from shared.config import EVENT_BUS, SECURITY_LOOKUP_CONCURRENCY, SECURITY_MODE
from shared.db import SessionLocal, init_db
from shared.events import AuditEvent, SecurityAssessed, VulnerabilityAssessed
from shared.extractor.vuln_extractor import extract_vulns
from shared.models import Document, SLABase, Vulnerability, VulnActionTemplate
from shared.worker import configure_logging, register_handlers, serve_forever
from security_service.assessment import assess_document
from security_service.bdu_client import BDUClient
from security_service.cache import get_cache
from security_service.cmdb import get_cmdb
from security_service.nvd_client import NVDClient

logger = logging.getLogger("fstec.security")

# РРЅСЉРµРєС†РёСЏ РєР»РёРµРЅС‚РѕРІ РґР»СЏ С‚РµСЃС‚РѕРІ (CI/offline): set_test_clients(nvd=..., bdu=..., cmdb=...)
_OVERRIDES: dict[str, object] = {}
_enrich: bool | None = None
_nvd: NVDClient | None = None
_bdu: BDUClient | None = None
_cmdb_instance = None


def set_test_clients(nvd=None, bdu=None, cmdb=None) -> None:
    global _enrich, _cmdb_instance
    _OVERRIDES.clear()
    _enrich = None
    _cmdb_instance = None
    if nvd is not None:
        _OVERRIDES["nvd"] = nvd
    if bdu is not None:
        _OVERRIDES["bdu"] = bdu
    if cmdb is not None:
        _OVERRIDES["cmdb"] = cmdb
    if nvd is not None or bdu is not None:
        _enrich = True


def set_enrich(enabled: bool) -> None:
    global _enrich
    _enrich = enabled


def _get_nvd() -> NVDClient | None:
    global _nvd
    if SECURITY_MODE != "live":
        return None
    if _nvd is None:
        _nvd = NVDClient(cache=get_cache())
    return _nvd


def _get_cmdb_instance():
    global _cmdb_instance
    if _OVERRIDES.get("cmdb") is not None:
        return _OVERRIDES["cmdb"]
    if _cmdb_instance is None:
        _cmdb_instance = get_cmdb() or None
    return _cmdb_instance


def _get_bdu() -> BDUClient | None:
    global _bdu
    if SECURITY_MODE != "live":
        return None
    if _bdu is None:
        _bdu = BDUClient(cache=get_cache())
    return _bdu


def _clip(value, limit: int) -> str:
    """Защитное усечение строки под длину колонки (NVD/BDU могут вернуть больше)."""
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit]


_VULN_LIMITS = {
    "cve_id": 50, "bdu_id": 50, "software": 500, "severity": 30,
    "cvss_version": 20, "cpe": 500, "fixed_version": 100, "patch_url": 1000,
    "current_version": 100, "target_version": 100, "source": 20,
    "affected_range": 10000, "action_type": 30,
}


def _store_assessments(db: Session, doc: Document, assessed: list[dict]) -> None:
    db.query(Vulnerability).filter(Vulnerability.document_id == doc.id).delete()
    templates = {t.action_type: t.content for t in db.query(VulnActionTemplate).all()}
    for a in assessed:
        rec = Vulnerability(
            document_id=doc.id,
            cve_id=_clip(a.get("cve_id", ""), _VULN_LIMITS["cve_id"]),
            bdu_id=_clip(a.get("bdu_id", ""), _VULN_LIMITS["bdu_id"]),
            description=a.get("description", ""),
            software=_clip(a.get("software", ""), _VULN_LIMITS["software"]),
            severity=_clip(a.get("severity", "unknown"), _VULN_LIMITS["severity"]),
            cvss_score=a.get("cvss_score"),
            cvss_version=a.get("cvss_version", ""),
            cpe=_clip(a.get("cpe", ""), _VULN_LIMITS["cpe"]),
            affected_range=_clip(a.get("affected_range", ""), _VULN_LIMITS["affected_range"]),
            fixed_version=_clip(a.get("fixed_version", ""), _VULN_LIMITS["fixed_version"]),
            patch_url=_clip(a.get("patch_url", ""), _VULN_LIMITS["patch_url"]),
            cmdb_match=a.get("cmdb_match", False),
            cmdb_error=a.get("cmdb_error", ""),
            current_version=_clip(a.get("current_version", ""), _VULN_LIMITS["current_version"]),
            target_version=_clip(a.get("target_version", ""), _VULN_LIMITS["target_version"]),
            source=_clip(a.get("source", "manual"), _VULN_LIMITS["source"]),
            recommendation=a.get("recommendation", templates.get("update", "")),
            is_applicable=a.get("is_applicable"),
            applicability_notes=_clip(a.get("applicability_notes", ""), 1500),
            action_type=_clip(a.get("action_type", ""), _VULN_LIMITS["action_type"]),
        )
        details = templates.get(rec.action_type, "")
        for key, value in (
            ("{{software}}", rec.software), ("{software}", rec.software),
            ("{{current_version}}", rec.current_version), ("{current_version}", rec.current_version),
            ("{{target_version}}", rec.target_version), ("{target_version}", rec.target_version),
            ("{{fixed_version}}", rec.target_version), ("{fixed_version}", rec.target_version),
        ):
            details = details.replace(key, value or "")
        rec.action_details = _clip(details, 1500)
        db.add(rec)


def _persist_assessment(doc_id: int, assessment) -> None:
    """Синхронная запись — выполняется в потоке (этап 4), чтобы ожидание NVD/BDU/CMDB
    других писем продолжалось, пока этот документ пишется в БД."""
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip security", doc_id)
            return
        sla, routing = assessment.sla, assessment.routing
        if doc.sla == "critical" or sla == "critical":
            sla = "critical"
            routing = "infosec"
        _store_assessments(db, doc, assessment.assessed)
        doc.sla, doc.routing = sla, routing
        doc.processing_stage = "assessed"
        doc.status = "assessed"
        cmdb_errors = sum(1 for a in assessment.assessed if a.get("cmdb_error"))
        db.add(SLABase(document_id=doc_id, sla=sla, routing=routing,
                       reason=f"cmdb_matches={sum(1 for a in assessment.assessed if a['cmdb_match'])}; "
                              f"cmdb_errors={cmdb_errors}"))
        db.commit()


async def handle_parsed_prefetch(topic: str, key: str, payload: dict) -> None:
    """Прогревает BDU/NVD-кэш в отдельной consumer group, пока LLM анализирует письмо."""
    text = payload.get("all_text") or payload.get("text") or ""
    if not text.strip():
        return
    try:
        vulns = await run_blocking(extract_vulns, text)
        bdu = _get_bdu()
        nvd = _get_nvd()
        jobs = []
        for v in vulns[:200]:
            bdu_id = (v.get("bdu_id", "") if isinstance(v, dict) else getattr(v, "bdu_id", "") or "").strip()
            cve_id = (v.get("cve_id", "") if isinstance(v, dict) else getattr(v, "cve_id", "") or "").strip()
            if bdu and bdu_id:
                jobs.append(bdu.get_bdu(bdu_id))
            if nvd and cve_id:
                jobs.append(nvd.get_cve(cve_id))
        if jobs:
            await bounded_gather(jobs, SECURITY_LOOKUP_CONCURRENCY, name="security-prefetch")
            logger.info("Prefetched %d security sources for doc %s", len(jobs), payload.get("document_id"))
    except Exception:  # noqa: BLE001 - prefetch не должен ломать конвейер
        logger.warning("Security prefetch failed", exc_info=True)


async def handle_analyzed(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    vulns_raw = payload.get("vulns_raw", [])

    nvd = _OVERRIDES.get("nvd", _get_nvd())
    bdu = _OVERRIDES.get("bdu", _get_bdu())
    cmdb = _get_cmdb_instance()

    enrich = _enrich if _enrich is not None else (SECURITY_MODE == "live")
    assessment = await assess_document(
        vulns_raw, cmdb=cmdb, enrich=enrich, nvd=nvd, bdu=bdu,
        letter_type=payload.get("classification") or "",
    )
    sla, routing = assessment.sla, assessment.routing

    await run_blocking(_persist_assessment, doc_id, assessment)

    bus = get_event_bus()
    if assessment.external_errors:
        reason = "; ".join(assessment.external_errors)[:2000]
        await bus.publish("audit.events", str(doc_id), _audit(doc_id, reason))
        await bus.publish("documents.failed", str(doc_id), {
            "event": "documents.failed",
            "document_id": doc_id,
            "stage": "security.assessed",
            "reason": reason,
        })
        logger.warning("External security sources unavailable for doc %s: %s", doc_id, reason)

    event = SecurityAssessed(
        document_id=doc_id,
        vulnerabilities=[VulnerabilityAssessed(**a) for a in assessment.assessed],
        sla=sla,
        routing=routing,
        external_errors=assessment.external_errors,
    )
    await bus.publish("security.assessed", str(doc_id), event.model_dump(mode="json"))
    logger.info("Assessed doc %s: %d vulns, sla=%s routing=%s",
                doc_id, len(assessment.assessed), sla, routing)


def _audit(doc_id: int, reason: str) -> dict:
    return AuditEvent(
        action="external_security_error", object_type="document",
        object_id=doc_id, document_id=doc_id, ip_address="",
    ).model_dump(mode="json")


def main():
    configure_logging()
    from shared.registry import register_service
    register_service("security")
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"document.analyzed": handle_analyzed})
        prefetch_bus = None
        if EVENT_BUS == "kafka":
            prefetch_bus = KafkaEventBus(group="fstec-prefetch")
            prefetch_bus.subscribe("document.parsed", handle_parsed_prefetch)
            await prefetch_bus.start()
        try:
            await serve_forever(bus, heartbeat_name="security")
        finally:
            if prefetch_bus is not None:
                await prefetch_bus.stop()
            from security_service.http_pool import close_clients
            await close_clients()
    asyncio.run(_run())


if __name__ == "__main__":
    main()