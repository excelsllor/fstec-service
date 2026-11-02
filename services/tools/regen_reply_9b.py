#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Перегенерация проектов ответов (этап reporting) в 9B E2E-БД после фикса backfill-мер.

Не запускает LLM-анализ заново: threats/vulns/iocs берутся из БД, пересоздаётся только
проект ответа (shared.generator.templated_reply.generate_reply) + GeneratedResponse.
Затем пересчитывается check_e2e_9b.json по той же логике evaluate() из e2e_generation.

Запуск (из services/):
    python -X utf8 tools/regen_reply_9b.py [9-99 9-107 ...]
без аргументов — все 22 письма.
"""
import asyncio
import base64
import json
import os
import re
import sys
import time
import difflib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_RUN_ID_LABEL = os.environ.get("FSTEC_E2E_RUN", "9b")
_UNIFIED_DB = Path(os.environ.get("FSTEC_E2E_DB", ROOT / "data" / "quality" / "e2e_runs.db"))
os.environ["FSTEC_DATA_DIR"] = str(_UNIFIED_DB.parent)
os.environ["DATABASE_URL"] = f"sqlite:///{_UNIFIED_DB}"
os.environ["FSTEC_EVENT_BUS"] = "memory"
os.environ["FSTEC_OCR_ENABLED"] = "false"
os.environ["FSTEC_LLM_PROVIDER"] = "vllm"
os.environ["VLLM_BASE_URL"] = os.environ.get("VLLM_BASE_URL", "http://127.0.0.1:8001/v1")
os.environ["VLLM_MODEL"] = os.environ.get("VLLM_MODEL", "Qwen3.5-9B")
os.environ["FSTEC_LLM_TIMEOUT_S"] = "600"
os.environ["FSTEC_SECURITY_MODE"] = "live"

from shared.db import SessionLocal, init_db  # noqa: E402
from shared.generator.response_generator import render_reply_docx  # noqa: E402
from shared.generator.templated_reply import generate_reply, persist_candidates  # noqa: E402
from shared.models import Document, GeneratedResponse, IoC, Report, Run, Threat, Vulnerability  # noqa: E402

init_db()


def _run_id() -> int | None:
    with SessionLocal() as db:
        r = db.query(Run).filter(Run.model == _RUN_ID_LABEL).order_by(Run.id.desc()).first()
        return r.id if r else None

MEASURE_KEYWORDS = ["вложени", "открывать", "загружать", "url", "фишинг", "песочниц",
                    "sandbox", "антивирус", "учетных записей", "привилегиями", "домен",
                    "ограничение обращений", "мониторинг", "инструктаж", "сертифицированн"]
WORD = re.compile(r"[а-яёa-z0-9]+")
NORM = re.compile(r"[^а-яёa-z0-9 ]+", re.IGNORECASE | re.UNICODE)


def norm(s):
    return NORM.sub(" ", s.lower())


def tok(s):
    return " ".join(WORD.findall(s.lower()))


def strip_cmdb(text: str) -> str:
    """Исключает из сравнения фрагменты, зависящие от CMDB заказчика (нет доступа к базе
    ПО заказчика): текущую версию в рекомендации «Обновить {ПО} с {current} до {fixed}»
    и утверждение «Используемая версия … не подвержена уязвимости» (проверка применяемости)."""
    out = text or ""
    out = re.sub(r"(\bОбновить\b[^.]*?)\bс\s+v?[0-9][\w\-.()]*\s+до\s+", r"\1до ", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"Используемая версия[^.]*?не подвержена[^.]*\.?", " ", out,
                 flags=re.IGNORECASE)
    return out


def _vuln_dict(v: Vulnerability) -> dict:
    return {
        "cve_id": v.cve_id or "",
        "bdu_id": v.bdu_id or "",
        "description": v.description or "",
        "software": v.software or "",
        "severity": v.severity or "unknown",
        "cvss_score": v.cvss_score,
        "cvss_version": v.cvss_version or "",
        "affected_range": v.affected_range or "",
        "fixed_version": v.fixed_version or "",
        "patch_url": v.patch_url or "",
        "current_version": v.current_version or "",
        "target_version": v.target_version or "",
        "recommendation": v.recommendation or "",
        "cmdb_match": bool(v.cmdb_match),
        "source": v.source or "manual",
    }


def regen_one(doc_id: int) -> dict:
    rid = _run_id()
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            return {"id": doc_id, "error": "doc not found"}

        iocs = db.query(IoC).filter(IoC.document_id == doc_id).all()
        domains = [i.value for i in iocs if i.ioc_type == "domain"]
        ips = [i.value for i in iocs if i.ioc_type == "ip"]

        vulns = [_vuln_dict(v) for v in
                 db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()]

        threat_rows = db.query(Threat).filter(Threat.document_id == doc_id).order_by(Threat.number).all()
        blocks = [{
            "id": t.id, "number": t.number, "threat_type": t.threat_type, "theme": t.theme,
            "group_name": t.group_name, "archive_name": t.archive_name, "exe_name": t.exe_name,
            "malware_type": t.malware_type, "description": t.description,
        } for t in threat_rows]

        rep = generate_reply(
            db=db, doc_id=doc.id, letter_type=doc.letter_type, blocks=blocks,
            addr_count=len(domains) + len(ips), active_vulns=vulns,
            addresses=sorted({*domains, *ips}),
        )
        if rep["candidates"]:
            for i, c in enumerate(rep["candidates"]):
                rep["candidates"][i]["threat_id"] = (blocks[i]["id"] if i < len(blocks) else None)
            persist_candidates(db, doc.id, rep["candidates"])

        # обновляем существующий ответ (текущий план/текст)
        existing = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id)
                    .order_by(GeneratedResponse.id.desc()).first())
        reply_text = rep["text"]
        reply_docx = render_reply_docx(reply_text)
        if existing:
            existing.content = reply_text
            existing.edited_content = base64.b64encode(reply_docx).decode("ascii")
            existing.plan_json = rep["plan_json"]
            existing.updated_at = datetime.now(timezone.utc)
        else:
            db.add(GeneratedResponse(document_id=doc.id, content=reply_text,
                                     edited_content=base64.b64encode(reply_docx).decode("ascii"),
                                     plan_json=rep["plan_json"]))
        db.commit()

        plan = json.loads(rep["plan_json"])
        blks = plan.get("blocks") or []
        lens = [len((b.get("measures") or [])) for b in blks]
        return {
            "id": doc.letter_number or str(doc_id),
            "letter_number": doc.letter_number, "letter_type": doc.letter_type,
            "llm": plan.get("llm"), "blocks": len(blks),
            "empty_blocks": sum(1 for b in blks if not (b.get("measures"))),
            "measures_per_block": lens[:12],
            "reply_chars": len(reply_text),
            "n_threats": len(threat_rows),
        }


def evaluate(n: str, ref_text: str, ref_alt_text: str = "") -> dict:
    row = {}
    rid = _run_id()
    with SessionLocal() as db:
        doc = (db.query(Document)
               .filter(Document.source_filename == f"{n}.pdf")
               .filter(Document.run_id == rid)
               .order_by(Document.id.desc()).first())
        if not doc:
            return {"id": n, "error": "doc not found"}
        threats = db.query(Threat).filter(Threat.document_id == doc.id).order_by(Threat.number).all()
        resp = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id)
                .order_by(GeneratedResponse.id.desc()).first())
        rep = db.query(Report).filter(Report.document_id == doc.id).first()
        row = {
            "id": n, "status": doc.status, "stage": doc.processing_stage,
            "letter_type": doc.letter_type, "letter_number": doc.letter_number,
            "letter_date": doc.letter_date, "sla": doc.sla, "routing": doc.routing,
            "n_threats": len(threats),
            "threats": [{"number": t.number, "threat_type": t.threat_type,
                         "theme": t.theme, "group_name": t.group_name} for t in threats],
            "report_file": rep.file_path if rep else None,
            "reply": resp.content if resp else "",
            "reply_chars": len(resp.content) if resp else 0,
        }
    if ref_text and row.get("reply"):
        rn, un = norm(strip_cmdb(ref_text)), norm(strip_cmdb(row["reply"]))
        rw = WORD.findall(rn)
        uw = WORD.findall(un)
        ratio = round(difflib.SequenceMatcher(None, uw, rw).ratio(), 3)
        row["ratio"] = ratio
        if ref_alt_text:
            rn2 = norm(strip_cmdb(ref_alt_text))
            ratio2 = round(difflib.SequenceMatcher(None, uw, WORD.findall(rn2)).ratio(), 3)
            row["ratio_alt"] = ratio2
            if ratio2 > ratio:
                rn, ratio = rn2, ratio2
                row["ratio"] = ratio
        row["num_ok"] = bool(row["letter_number"]) and tok(row["letter_number"]) in rn
        date_cands = [tok(row["letter_date"])]
        d = row["letter_date"]
        if d and re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
            date_cands.append(tok(f"{d[8:10]}.{d[5:7]}.{d[0:4]}"))
        row["date_ok"] = bool(d) and any(c in rn for c in date_cands)
        kw_hit = [k for k in MEASURE_KEYWORDS if k in rn]
        kw_miss = [k for k in kw_hit if k not in un]
        row["kw_overlap"] = f"{len(kw_hit) - len(kw_miss)}/{len(kw_hit)}"
        row["kw_missing"] = kw_miss
        row["reply_has_compromise_measures"] = ("контроль журналов" in row["reply"]) or (
            "внеплановое сканирование" in row["reply"])
        row["reply_sections"] = len(re.findall(r"(?m)^\d+\. В целях предотвращения", row["reply"]))
    return row


def _ensure_source_filename(db, doc):
    if not doc.source_filename:
        n = (doc.letter_number or "doc").replace("/", "-")
        doc.source_filename = f"{n}.pdf"
        db.commit()
        return f"{n}.pdf"
    return doc.source_filename


def main():
    root = Path(r"C:\Users\artyom\Desktop\лгту хуйня")
    out_dir = ROOT / "data" / "quality" / "e2e" / _RUN_ID_LABEL
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = ROOT / "data" / "quality" / f"check_e2e_{_RUN_ID_LABEL}.json"

    old_rows = {}
    if report_path.is_file():
        try:
            old_rows = {r["id"]: r for r in json.loads(report_path.read_text(encoding="utf-8")).get("rows", [])}
        except Exception:
            old_rows = {}

    only = set(sys.argv[1:]) or None
    rid = _run_id()

    with SessionLocal() as db:
        ids = [{'id': d.id, 'sn': _ensure_source_filename(db, d)}
               for d in db.query(Document)
               .filter(Document.run_id == rid).order_by(Document.id).all()]
    if only:
        ids = [x for x in ids if any(o in x['sn'] or o in str(x['id']) for o in only)]

    regen = []
    t0 = time.time()
    for i, info in enumerate(ids, 1):
        n = Path(info['sn']).stem
        try:
            r = regen_one(info['id'])
            regen.append(r)
            print(f"[{i}/{len(ids)}] {n} llm={r.get('llm')} blocks={r.get('blocks')} "
                  f"empty={r.get('empty_blocks')} chars={r.get('reply_chars')}", flush=True)
        except Exception as e:
            regen.append({"id": n, "error": str(e)})
            print(f"[{i}/{len(ids)}] {n} ERROR: {e}", flush=True)

    print(f"\nregen done in {round(time.time() - t0)}s", flush=True)

    # пересчёт check_e2e_9b.json
    casedirs = {p.name for p in root.iterdir()
                if p.is_dir() and re.fullmatch(r"9-\d+", p.name)}
    rows = []
    for info in ids:
        n = Path(info['sn']).stem
        ref, ref_alt = root / f"Ответ на письмо {n}.docx", None
        sub = root / n if n in casedirs else root
        ref_dir = sub / f"Ответ  на письмо {n}.docx" if sub != root else root / f"Ответ на письмо {n}.docx"
        alt = root / f"!Ответ на письмо {n}.docx"
        if not ref.is_file():
            ref = ref_dir
        if not ref.is_file() and alt.is_file():
            ref, ref_alt = alt, ref
        elif alt.is_file():
            ref_alt = alt
        try:
            ref_text = ""
            if ref.is_file():
                from shared.parsers import parse_file
                ref_text = parse_file(ref).text or ""
            ref_alt_text = ""
            if ref_alt and ref_alt.is_file():
                ref_alt_text = parse_file(ref_alt).text or ""
            row = evaluate(n, ref_text, ref_alt_text)
            row["error"] = None
            old = old_rows.get(row["id"])
            if old and not row.get("elapsed_s"):
                row["elapsed_s"] = old.get("elapsed_s")
        except Exception as e:
            row = {"id": n, "error": str(e)}
        rows.append(row)
        print(f"eval [{n}] ratio={row.get('ratio')} kw={row.get('kw_overlap')} "
              f"chars={row.get('reply_chars')} err={row.get('error')}", flush=True)

    report_path.write_text(json.dumps({"stage": "e2e_generation", "rows": rows},
                                      ensure_ascii=False, indent=1), encoding="utf-8")

    with open(out_dir / "regen_summary.json", "w", encoding="utf-8") as f:
        json.dump({"regen": regen}, f, ensure_ascii=False, indent=1)
    print(f"\ncheck: {report_path}")


if __name__ == "__main__":
    main()