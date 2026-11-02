#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Пересчёт ratio в check_e2e_*.json с нормализацией без CMDB-метрик.

Исключаются фрагменты, зависящие от базы ПО заказчика (нет доступа): текущая версия в
рекомендации «Обновить {ПО} с {current} до {fixed}» и «Используемая версия … не
подвержена уязвимости». Reply берётся из самого чек-файла (LLM не запускается).

Запуск (из services/):
    python -X utf8 tools/reeval_ratio.py [check_e2e_14b.json check_e2e_9b.json ...]
"""
import json
import re
import sys
import difflib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORK = Path(r"C:\Users\artyom\Desktop\лгту хуйня")

MEASURE_KEYWORDS = ["вложени", "открывать", "загружать", "url", "фишинг", "песочниц",
                    "sandbox", "антивирус", "учетных записей", "привилегиями", "домен",
                    "ограничение обращений", "мониторинг", "инструктаж", "сертифицированн"]
WORD = re.compile(r"[а-яёa-z0-9]+")
NORM = re.compile(r"[^а-яёa-z0-9 ]+", re.IGNORECASE | re.UNICODE)


def norm(s):
    return NORM.sub(" ", s.lower() or "")


def strip_cmdb(text: str) -> str:
    out = text or ""
    out = re.sub(r"(\bОбновить\b[^.]*?)\bс\s+v?[0-9][\w\-.()]*\s+до\s+", r"\1до ", out,
                 flags=re.IGNORECASE)
    out = re.sub(r"Используемая версия[^.]*?не подвержена[^.]*\.?", " ", out,
                 flags=re.IGNORECASE)
    return out


def find_ref(n: str) -> tuple[Path, Path | None]:
    ref = WORK / f"Ответ на письмо {n}.docx"
    sub = WORK / n
    if sub.is_dir():
        ref = sub / f"Ответ  на письмо {n}.docx"
        if not ref.is_file():
            alt = sub / f"Ответ на письмо {n}.docx"
            if alt.is_file():
                ref = alt
    alt = WORK / f"!Ответ на письмо {n}.docx"
    if not ref.is_file() and alt.is_file():
        return alt, None
    return ref, (alt if (alt.is_file() and ref.is_file()) else None)


def reeval_row(row: dict) -> dict:
    n = row.get("id", "")
    ref, ref_alt = find_ref(n)
    r = dict(row)
    reply = r.get("reply") or ""
    if not reply:
        return r
    try:
        from shared.parsers import parse_file
    except Exception:
        return r
    ref_text = parse_file(ref).text or "" if ref.is_file() else ""
    if not ref_text:
        return r
    rn, un = norm(strip_cmdb(ref_text)), norm(strip_cmdb(reply))
    rw, uw = WORD.findall(rn), WORD.findall(un)
    ratio = round(difflib.SequenceMatcher(None, uw, rw).ratio(), 3)
    if ref_alt and ref_alt.is_file():
        alt_text = parse_file(ref_alt).text or ""
        if alt_text:
            ratio2 = round(difflib.SequenceMatcher(
                None, uw, WORD.findall(norm(strip_cmdb(alt_text)))).ratio(), 3)
            if ratio2 > ratio:
                rn, ratio = norm(strip_cmdb(alt_text)), ratio2
    r["ratio"] = ratio
    r["reply_chars"] = len(reply)
    kw_hit = [k for k in MEASURE_KEYWORDS if k in rn]
    kw_miss = [k for k in kw_hit if k not in un]
    r["kw_overlap"] = f"{len(kw_hit) - len(kw_miss)}/{len(kw_hit)}"
    r["kw_missing"] = kw_miss
    return r


def main():
    sys.path.insert(0, str(ROOT))
    q = ROOT / "data" / "quality"
    files = sys.argv[1:] or [q / "check_e2e_14b.json", q / "check_e2e_9b.json"]
    for f in files:
        p = Path(f) if Path(f).is_file() else q / f
        if not p.is_file():
            print(f"skip {p.name}: not found")
            continue
        data = json.loads(p.read_text(encoding="utf-8"))
        rows = [reeval_row(r) for r in data.get("rows", [])]
        data = {"stage": "e2e_generation", "rows": rows}
        p.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        for r in sorted(rows, key=lambda x: int(x["id"].split("-")[1])):
            print(f"  {r['id']:8s} ratio={r.get('ratio')} kw={r.get('kw_overlap')} err={r.get('error')}")
        print(f"updated: {p}")


if __name__ == "__main__":
    main()