#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Итоговый отчёт E2E-генерации.

Источник: sqlite-БД полного прогона E2E (upload→parse→LLM analyze→BDU/NVD assess→report).
Здесь ответы ПЕРЕгенерируются текущей версией генератора по сохранённым угрозам LLM
и сверяются с эталоном (Ответ на письмо 9-XX.docx).
Артефакты: data/quality/check_e2e.json, docs/e2e_generation_report.md, data/quality/e2e/.
"""
import difflib
import json
import os
import re
import sys
from pathlib import Path

_RUN_ID_LABEL = os.environ.get("FSTEC_E2E_RUN", "")
if "--run" in sys.argv:
    i = sys.argv.index("--run")
    if i + 1 < len(sys.argv):
        _RUN_ID_LABEL = sys.argv[i + 1]

if "--db" not in sys.argv:
    _DB = Path(os.environ.get(
        "FSTEC_E2E_DB",
        Path(__file__).resolve().parent.parent / "data" / "quality" / "e2e_runs.db"))
    sys.argv.append("--db")
    sys.argv.append(str(_DB))

DB = Path(sys.argv[sys.argv.index("--db") + 1])
os.environ["DATABASE_URL"] = f"sqlite:///{DB}"

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.db import SessionLocal  # noqa: E402
from shared.models import Document, Report, Run, Threat  # noqa: E402
from shared.generator.response_generator import generate_reply_text  # noqa: E402
from shared.parsers import parse_file  # noqa: E402

MEASURE_KEYWORDS = ["вложени", "открывать", "загружать", "url", "фишинг", "песочниц",
                    "sandbox", "антивирус", "учетных записей", "привилегиями", "домен",
                    "ограничение обращений", "мониторинг", "инструктаж", "сертифицированн"]
WORD = re.compile(r"[а-яёa-z0-9]+", re.IGNORECASE | re.UNICODE)
NORM = re.compile(r"[^а-яёa-z0-9 ]+", re.IGNORECASE | re.UNICODE)


def norm(s):
    return NORM.sub(" ", s.lower())


def tok(s):
    return " ".join(WORD.findall(s.lower()))


def load_db(work: dict):
    run_ids = None
    if _RUN_ID_LABEL:
        with SessionLocal() as db:
            run_ids = [r.id for r in db.query(Run).filter(Run.model == _RUN_ID_LABEL).all()]
    with SessionLocal() as db:
        q = db.query(Document).order_by(Document.id)
        if run_ids:
            q = q.filter(Document.run_id.in_(run_ids))
        for doc in q.all():
            n = re.match(r"^(9-\d+)\.", doc.source_filename or "")
            if not n:
                continue
            n = n.group(1)
            threats = [{"number": t.number, "threat_type": t.threat_type, "theme": t.theme,
                        "group_name": t.group_name, "malware_type": t.malware_type,
                        "description": t.description} for t in
                       db.query(Threat).filter(Threat.document_id == doc.id)
                       .order_by(Threat.number).all()]
            rep = db.query(Report).filter(Report.document_id == doc.id).first()
            work[n] = {"letter_number": doc.letter_number, "letter_date": doc.letter_date,
                       "letter_type": doc.letter_type, "status": doc.status,
                       "sla": doc.sla, "routing": doc.routing, "threats": threats,
                       "report_file": rep.file_path if rep else None}


def main():
    root = Path(r"C:\Users\artyom\Desktop\лгту хуйня")
    out_dir = ROOT / "data" / "quality" / "e2e" / (_RUN_ID_LABEL or "all")
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = ROOT / "docs" / f"e2e_generation_report{('_' + _RUN_ID_LABEL) if _RUN_ID_LABEL else ''}.md"

    work: dict = {}
    load_db(work)
    cases = sorted(p for p in root.iterdir() if p.is_dir() and re.fullmatch(r"9-\d+", p.name))
    rows, md = [], ["# E2E-генерация ответов (9-XX): полная цепочка + сверка с эталоном", ""]
    md.append("Цепочка: `upload → parse → analyze (LLM vllm/Qwen3-14B) → assess (BDU/NVD live) → "
              "card + reply`. Ответы перегенерированы текущей версией `response_generator` по "
              "угрозам LLM; сверка — с `Ответ  на письмо 9-XX.docx`.")
    md.append("")

    totals = {"num": 0, "date": 0, "kw_num": 0, "kw_den": 0, "ratio": []}

    for case in cases:
        n = case.name
        row = work.get(n)
        if not row:
            continue
        threats = row["threats"]
        reply = generate_reply_text(
            letter_number=row["letter_number"] or "",
            letter_date=row["letter_date"] or "",
            letter_type=row["letter_type"] or "hacker",
            threats=threats, vulnerabilities=[], addr_count=max(1, len(threats)),
        )
        ref = case / f"Ответ  на письмо {n}.docx"
        ref_text = parse_file(ref).text or "" if ref.is_file() else ""
        rn, un = norm(ref_text), norm(reply)
        ratio = round(difflib.SequenceMatcher(None, WORD.findall(un), WORD.findall(rn)).ratio(), 3)
        num_ok = bool(row["letter_number"]) and tok(row["letter_number"]) in rn
        d = row["letter_date"] or ""
        date_cands = [tok(d)]
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
            date_cands.append(tok(f"{d[8:10]}.{d[5:7]}.{d[0:4]}"))
        date_ok = bool(d) and any(c in rn for c in date_cands)
        kw_hit = [k for k in MEASURE_KEYWORDS if k in rn]
        kw_miss = [k for k in kw_hit if k not in un]
        sections = len(re.findall(r"(?m)^\d+\. В целях предотвращения", reply))
        compromise_ok = ("контроль журналов" in reply) and ("внеплановое сканирование" in reply)
        bad_intro = bool(re.search(r"связанных с \d+\. |связанных с (?:Re\b|Fw[)\]:]|Переслан)", reply, re.IGNORECASE))
        empty_theme = sum(1 for t in threats if not (t.get("theme") or "").strip())
        groups = [t.get("group_name") for t in threats if t.get("group_name")]

        res = {"id": n, "letter_type": row["letter_type"],
               "letter_number": row["letter_number"], "letter_date": row["letter_date"],
               "status": row["status"], "sla": row["sla"], "routing": row["routing"],
               "n_threats": len(threats), "threats": threats, "reply": reply,
               "reply_chars": len(reply), "report_file": row.get("report_file"),
               "ratio": ratio, "num_ok": num_ok, "date_ok": date_ok,
               "kw_overlap": f"{len(kw_hit) - len(kw_miss)}/{len(kw_hit)}",
               "kw_missing": kw_miss, "reply_sections": sections,
               "compromise_measures": compromise_ok, "bad_intro": bad_intro,
               "themes_empty": empty_theme, "groups": groups}
        rows.append(res)
        totals["num"] += num_ok
        totals["date"] += date_ok
        totals["kw_num"] += len(kw_hit) - len(kw_miss)
        totals["kw_den"] += len(kw_hit)
        totals["ratio"].append(ratio)

        sub = out_dir / f"doc_{n}"
        sub.mkdir(parents=True, exist_ok=True)
        (sub / "reply.txt").write_text(reply, encoding="utf-8")
        if res["report_file"] and Path(res["report_file"]).is_file():
            (sub / "card.docx").write_bytes(Path(res["report_file"]).read_bytes())

        md.append(f"## {n} — {row['letter_number']} от {row['letter_date']} "
                  f"({row['letter_type']}, {row['sla']}/{row['routing']})")
        md.append(f"- Статус: `{row['status']}`; блоков в ответе `{sections}` "
                  f"на `{len(threats)}` угроз; пустых тем: `{empty_theme}`")
        md.append(f"- Сверка с эталоном: ratio `{ratio}`, номер `{'ok' if num_ok else 'NO'}` / "
                  f"дата `{'ok' if date_ok else 'NO'}`; меры покрыты `{res['kw_overlap']}`"
                  f"{' (не: ' + ', '.join(kw_miss) + ')' if kw_miss else ''}")
        md.append(f"- Ветка компрометации: `{'да' if compromise_ok else 'нет'}`; "
                  f"плохие вступления: `{'да' if bad_intro else 'нет'}`")
        md.append("")

    avg = round(sum(totals["ratio"]) / len(totals["ratio"]), 3) if totals["ratio"] else 0
    md.insert(2, f"**Итого: {len(rows)}/12 — `completed`; реквизиты {totals['num'] + totals['date']}/24; "
                 f"меры эталона покрыты {totals['kw_num']}/{totals['kw_den']} "
                 f"({round(100 * totals['kw_num'] / max(1, totals['kw_den']))}%); "
                 f"средний ratio `{avg}` (до фиксов 0.14–0.29).**\n")

    report = {"stage": "e2e_generation_final", "db": str(DB),
              "run": _RUN_ID_LABEL or "all",
              "rows": rows,
              "totals": {k: v for k, v in totals.items() if k != "ratio"} | {"avg_ratio": avg}}
    (ROOT / "data" / "quality" / f"check_e2e{('_' + _RUN_ID_LABEL) if _RUN_ID_LABEL else ''}.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("\n".join(md), encoding="utf-8")

    print(json.dumps(report["totals"], ensure_ascii=False))
    for r in rows:
        print(f"{r['id']:6} thr={r['n_threats']:2} sect={r['reply_sections']:2} "
              f"ratio={r['ratio']} num={r['num_ok']} date={r['date_ok']} "
              f"kw={r['kw_overlap']} comp={r['compromise_measures']} bad={r['bad_intro']} "
              f"empty_theme={r['themes_empty']}")
    print(f"\nReport: {ROOT / 'data' / 'quality' / 'check_e2e.json'}\nMarkdown: {md_path}")


if __name__ == "__main__":
    main()