#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 8 проверки: парсеры всех поддерживаемых форматов (ТЗ 2.2).

Каждый формат: билдер -> parse_bytes -> текст не пуст и содержит ключевые
маркеры IoC/уязвимостей. DOC — как реальный бинарный .doc.
OCR: ocr_pdf_bytes на текстовом PDF — ожидаем graceful-путь (текст или errs).
Артефакт: data/quality/check_stage8.json
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.parsers import parse_bytes
from tests.formats import BUILDERS, IOC_MARKERS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage8.json"))
    args = ap.parse_args()

    rows = []
    for ext, builder in BUILDERS.items():
        try:
            content = builder()
            res = parse_bytes(f"sample{ext}", content)
        except Exception as e:  # noqa: BLE001
            rows.append({"format": ext, "ok": False, "error": f"{type(e).__name__}: {e}"})
            print(f"  {ext:6} FAIL {type(e).__name__}: {e}")
            continue
        text = res.text or ""
        missing = [m for m in IOC_MARKERS if m.lower() not in text.lower()]
        ok = len(text) >= 50 and not missing
        rows.append({"format": ext, "ok": ok, "chars": len(text),
                     "missing": missing, "tables": len(res.tables or [])})
        print(f"  {ext:6} {'OK ' if ok else 'WARN'} chars={len(text):5} tables={len(res.tables or [])} "
              f"missing={missing}")

    ocr_result = {}
    try:
        from shared.parsers.ocr import ocr_pdf_bytes
        from tests.formats import make_pdf_bytes
        try:
            text, errs = ocr_pdf_bytes(make_pdf_bytes(), dpi=150)
            ocr_result = {"ok": bool(text), "chars": len(text), "errors": errs}
            print(f"  ocr    {'OK ' if text else 'UNAVAIL'} chars={len(text)} errors={errs}")
        except Exception as e:  # noqa: BLE001
            ocr_result = {"ok": False, "error": f"{type(e).__name__}: {e}"}
            print(f"  ocr    FAIL {type(e).__name__}: {e}")
    except ImportError as e:
        ocr_result = {"ok": False, "error": f"import: {e}"}
        print(f"  ocr    UNAVAIL import: {e}")

    report = {"stage": 8, "formats": rows, "ocr": ocr_result}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {args.out}")
    ok_count = sum(1 for r in rows if r["ok"])
    print(f"formats OK: {ok_count}/{len(rows)}" + (" | ocr ok" if ocr_result.get("ok") else " | ocr unavailable"))


if __name__ == "__main__":
    main()