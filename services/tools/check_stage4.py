#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 4 проверки: NER (стандартные сущности) на реальных письмах.

hueristic : extract_standard_ner(main) -> организации/сроки/контакты
llm-cases: те же сущности через Qwen3 (provider) для указанных писем — кросс-сверка.
Артефакт: data/quality/check_stage4.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.ner import extract_standard_ner


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage4.json"))
    ap.add_argument("--llm-cases", default="9-104,9-89",
                    help="Письма для LLM-кросс-сверки сущностей (запятые)")
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    llm_names = [x.strip() for x in args.llm_cases.split(",") if x.strip() in corpus]

    rows = []
    for n, c in corpus.items():
        text = c["main"]
        ner = extract_standard_ner(text)
        rows.append({
            "id": n,
            "organizations": ner.organizations,
            "deadlines": ner.deadlines,
            "contacts": ner.contacts,
        })
        print(f"  {n:6} orgs={ner.organizations} deadlines={ner.deadlines} contacts={ner.contacts}")

    print("\n=== LLM-кросс-сверка сущностей ===")
    from llm_service.provider import get_provider
    provider = get_provider()
    llm = {}
    for n in llm_names:
        text = corpus[n].get("full") or corpus[n]["main"]
        ts = time.perf_counter()
        res = provider.analyze(text, hint=None)
        dt = time.perf_counter() - ts
        ents = res.entities
        llm[n] = {"entities": ents, "used": res.llm_used, "sec": round(dt, 1)}
        print(f"  {n:6} [{dt:.1f}s used={res.llm_used}] entities:")
        for e in ents:
            print(f"       {e['type']:12} = {e['value']!r}")
        h = extract_standard_ner(text)
        print(f"       heuristic: orgs={h.organizations} deadlines={h.deadlines} contacts={h.contacts}")

    report = {"stage": 4, "rows": rows, "llm_cross": llm}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {out}")


if __name__ == "__main__":
    main()