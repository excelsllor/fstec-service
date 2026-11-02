#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 1 проверки: категория по отдельным компонентам (without полного конвейера).

  regex-only : _detect_type на 12 письмах
  vllm-only  : провайдер (Qwen3 через llama.cpp) БЕЗ regex-подсказки — на указанных письмах
Артефакт: data/quality/check_stage1.json
"""
import argparse
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.letter_analyzer import analyze_letter


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage1.json"))
    ap.add_argument("--llm-cases", default="9-77,9-104,9-99",
                    help="Подмножество писем для vllm-only (запятые)")
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    gold = {n: c["gold"]["classification"] for n, c in corpus.items()}

    print("=== Stage 1a: категория regex-only (_detect_type, первые 5000 симв) ===")
    regex = {}
    for n, c in corpus.items():
        g = gold[n]
        p = analyze_letter(c["main"]).letter_type
        regex[n] = p
        print(f"  {n:6} gold={g:10} regex={p:10} {'OK' if p == g else 'MISS'}")
    ok = sum(1 for n in gold if regex[n] == gold[n])
    print(f"  regex-only accuracy: {ok}/{len(gold)}")

    print("\n=== Stage 1c: категория vLLM-only (без regex-подсказки, полный текст) ===")
    from llm_service.provider import get_provider
    provider = get_provider()
    llm_names = [x.strip() for x in args.llm_cases.split(",") if x.strip() in corpus]
    llm = {}
    t0 = time.perf_counter()
    for n in llm_names:
        text = corpus[n].get("full") or corpus[n]["main"]
        ts = time.perf_counter()
        res = provider.analyze(text, hint=None)
        dt = time.perf_counter() - ts
        pred = res.classification
        llm[n] = pred
        print(f"  {n:6} gold={gold[n]:10} llm={pred:10} used={res.llm_used} {dt:.1f}s "
              f"{'OK' if pred == gold[n] else 'MISS'}")
    total_t = time.perf_counter() - t0
    ok_l = sum(1 for n in llm if llm[n] == gold[n])
    print(f"  vllm-only accuracy (на {len(llm)}): {ok_l}/{len(llm)} | wall={total_t:.0f}s")

    report = {
        "stage": 1,
        "regex_only": {"per_case": regex,
                       "accuracy": round(ok / len(gold), 4), "correct": ok, "total": len(gold)},
        "engine": sys.version.split()[0],
        "vllm_only": {"per_case": llm,
                      "accuracy": round(ok_l / len(llm), 4) if llm else None,
                      "cases": len(llm), "wall_s": round(total_t, 1)},
        "provider_kind": str(provider.kind.value),
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {out}")


if __name__ == "__main__":
    main()