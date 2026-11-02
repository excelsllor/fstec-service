#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Трёхстороннее сравнение E2E-прогонов Qwen3-14B / Qwen3-8B / Qwen3.5-9B.

Источники (по умолчанию в data/quality/):
  check_e2e_14b.json  — прогон Qwen3-14B-IQ3_XXS (22 письма)
  check_e2e_8b.json   — прогон Qwen3-8B-Q4_K_M (22 письма)
  check_e2e_9b.json   — прогон Qwen3.5-9B-M-TS-Q4_K_M (22 письма)

На выходе: data/quality/comparison_14b_vs_8b_vs_9b.md + печать агрегатов.

Запуск (из services/):
    python -X utf8 tools/report_3way.py [check_14b.json] [check_8b.json] [check_9b.json]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(p: Path) -> dict:
    data = json.loads(Path(p).read_text(encoding="utf-8"))
    return {r["id"]: r for r in data.get("rows", [])}


def num(r, key):
    v = r.get(key) if r else None
    return v if isinstance(v, (int, float)) else None


def avg(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 3) if xs else None


def fmt(v):
    return f"{v}" if v is not None else "-"


def fmt1(v):
    return f"{v:.1f}" if v is not None else "-"


def main():
    arg = lambda n, d: Path(sys.argv[n]) if len(sys.argv) > n else d
    q = ROOT / "data" / "quality"
    rows14 = load(arg(1, q / "check_e2e_14b.json"))
    rows8 = load(arg(2, q / "check_e2e_8b.json"))
    rows9 = load(arg(3, q / "check_e2e_9b.json"))

    ids = sorted({**rows14, **rows8, **rows9}, key=lambda i: int(i.split("-")[1]))
    by_type = {"hacker": [], "vulnerability": [], "compromise": [], "other": []}
    for i in ids:
        t = (rows14.get(i) or rows8.get(i) or rows9.get(i)).get("letter_type") or "other"
        by_type.setdefault(t, []).append(i)

    lines = ["# Сравнение Qwen3-14B vs Qwen3-8B vs Qwen3.5-9B (E2E, 22 письма)",
             "",
             "Правила: ratio — совпадение с эталоном (выше лучше); сек — время на письмо",
             "(ниже лучше); kw — доля ключевых мер эталона в ответе.",
             "",
             "| id | тип | ratio 14B | ratio 8B | ratio 9B | сек 14B | сек 8B | сек 9B | kw 14B | kw 8B | kw 9B |",
             "|----|-----|-----------|----------|----------|---------|--------|--------|--------|-------|-------|"]
    for i in ids:
        r14, r8, r9 = num(rows14.get(i), "ratio"), num(rows8.get(i), "ratio"), num(rows9.get(i), "ratio")
        s14, s8, s9 = num(rows14.get(i), "elapsed_s"), num(rows8.get(i), "elapsed_s"), num(rows9.get(i), "elapsed_s")
        k14, k8, k9 = num(rows14.get(i), "kw_overlap"), num(rows8.get(i), "kw_overlap"), num(rows9.get(i), "kw_overlap")
        t = (rows14.get(i) or rows8.get(i) or rows9.get(i)).get("letter_type") or "other"
        lines.append(f"| {i} | {t} | {fmt(r14)} | {fmt(r8)} | {fmt(r9)} | "
                     f"{fmt1(s14)} | {fmt1(s8)} | {fmt1(s9)} | {fmt(k14)} | {fmt(k8)} | {fmt(k9)} |")

    def agg_rows(rs, key):
        return [num(rs.get(i), key) for i in ids]

    A14, A8, A9 = agg_rows(rows14, "ratio"), agg_rows(rows8, "ratio"), agg_rows(rows9, "ratio")
    S14, S8, S9 = agg_rows(rows14, "elapsed_s"), agg_rows(rows8, "elapsed_s"), agg_rows(rows9, "elapsed_s")

    lines += ["",
              "## Агрегаты по типам (avg ratio)",
              "",
              "| тип | 14B | 8B | 9B |",
              "|-----|-----|-----|-----|"]
    for t in ("hacker", "vulnerability", "compromise"):
        g = by_type.get(t, [])
        v = lambda rs: avg([num(rs.get(i), "ratio") for i in g])
        lines.append(f"| {t} | {fmt(v(rows14))} | {fmt(v(rows8))} | {fmt(v(rows9))} |")

    lines += ["",
              "## Скорость (сек/письмо)",
              "",
              "| метрика | 14B | 8B | 9B |",
              "|---------|-----|-----|-----|",
              f"| avg сек/письмо | {fmt1(avg(S14))} | {fmt1(avg(S8))} | {fmt1(avg(S9))} |",
              f"| сумма, сек | {fmt1(sum(S14))} | {fmt1(sum(S8))} | {fmt1(sum(S9))} |",
              f"| min | {fmt1(min(S14))} | {fmt1(min(S8))} | {fmt1(min(S9))} |",
              f"| max | {fmt1(max(S14))} | {fmt1(max(S8))} | {fmt1(max(S9))} |",
              "",
              "## Итог",
              "",
              f"- 14B: avg ratio **{avg(A14)}**, avg **{fmt1(avg(S14))} с/письмо**.",
              f"- 8B:  avg ratio **{avg(A8)}**, avg **{fmt1(avg(S8))} с/письмо**.",
              f"- 9B:  avg ratio **{avg(A9)}**, avg **{fmt1(avg(S9))} с/письмо**.",
              ""]

    out = q / "comparison_14b_vs_8b_vs_9b.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nComparison: {out}")
    print(json.dumps({"ratio_14b": avg(A14), "ratio_8b": avg(A8), "ratio_9b": avg(A9),
                      "sec_14b": avg(S14), "sec_8b": avg(S8), "sec_9b": avg(S9)},
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()