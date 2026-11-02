#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 8b: локальная проверка PaddleOCR на реальных PDF писем (тз 2.2/4.1).

Для каждого письма:
  - OCR полного PDF (dpi=200) + замер времени
  - сравнение с parsed-main: доля доменных индикаторов и ключевых фраз, difflib-ratio
  - фиксирует ошибки (модели/недоступность движка)
Артефакт: data/quality/check_ocr.json
"""
import argparse
import difflib
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.parsers.ocr import ocr_pdf_bytes

CASES = ["9-104", "9-77", "9-89"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--root", default=r"C:\Users\artyom\Desktop\лгту хуйня")
    ap.add_argument("--dpi", type=int, default=200)
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_ocr.json"))
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    root = Path(args.root)

    rows = []
    for n in CASES:
        pdf = root / n / f"{n}.pdf"
        if not pdf.is_file():
            print(f"  {n}: PDF не найден {pdf}")
            continue
        t0 = time.perf_counter()
        text, errors = ocr_pdf_bytes(pdf.read_bytes(), dpi=args.dpi)
        dt = time.perf_counter() - t0
        main = corpus[n]["main"]
        gold_doms = corpus[n]["gold"]["domains"]
        found_doms = [d for d in gold_doms if d.lower() in text.lower()]
        key_phrases = ["ФСТЭК", "хакерской группировкой", "фишингов", "архив",
                       "вредоносн", "заблокировать", "приняты"]
        hits = [k for k in key_phrases if k.lower() in text.lower()]
        r = difflib.SequenceMatcher(None, text.lower(), main.lower()).ratio()
        row = {"id": n, "chars": len(text), "sec": round(dt, 1), "errors": errors,
               "domains_found": len(found_doms), "domains_total": len(gold_doms),
               "keyword_hits": hits, "text_main_ratio": round(r, 3)}
        rows.append(row)
        print(f"  {n:6} chars={len(text):6} time={dt:5.1f}s errors={len(errors)} "
              f"doms={len(found_doms)}/{len(gold_doms)} hits={len(hits)}/{len(key_phrases)}")
        if errors:
            for e in errors[:3]:
                print(f"         ! {e}")
        print(f"         OCR head: {' '.join(text.split())[:120]}")

    report = {"stage": "8b", "dpi": args.dpi, "rows": rows,
              "engine": "paddle(cpu)"}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {args.out}")


if __name__ == "__main__":
    main()