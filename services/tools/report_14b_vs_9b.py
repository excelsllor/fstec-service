#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сравнение E2E-прогонов Qwen3-14B vs Qwen3.5-9B (22 письма, без 8B).

Источники (data/quality/): check_e2e_14b.json и check_e2e_9b.json.
На выходе: data/quality/comparison_14b_vs_9b.md + печать агрегатов.

Запуск (из services/):
    python -X utf8 tools/report_14b_vs_9b.py [check_14b.json] [check_9b.json]
"""
import json
import sys
from datetime import date
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


def pct(a, b):
    if b is None or a is None or b == 0:
        return ""
    return f"({'+' if a / b > 1 else ''}{round(100 * a / b - 100, 1)}%)"


def load_gold() -> dict:
    """Эталонные типы писем (data/quality/letter_types_gold.json). Пусто, если файла нет."""
    p = ROOT / "data" / "quality" / "letter_types_gold.json"
    if not p.is_file():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        return {}


def main():
    q = ROOT / "data" / "quality"
    p14 = Path(sys.argv[1]) if len(sys.argv) > 1 else q / "check_e2e_14b.json"
    p9 = Path(sys.argv[2]) if len(sys.argv) > 2 else q / "check_e2e_9b.json"
    r14, r9 = load(p14), load(p9)
    gold = load_gold()

    ids = sorted(r14.keys() | r9.keys(), key=lambda i: int(i.split("-")[1]))
    by_type = {}
    for i in ids:
        t = gold.get(i) or (r14.get(i) or r9.get(i)).get("letter_type") or "other"
        by_type.setdefault(t, []).append(i)

    lines = [f"# Сравнение Qwen3-14B vs Qwen3.5-9B (E2E, 22 письма, {date.today().isoformat()})",
             "",
             "Модели: 14B = Qwen_Qwen3-14B-IQ3_XXS, 9B = Qwen3.5-9B-M-TS-Q4_K_M",
             "(llama-server Vulkan 2.34.0, port 8001, ctx 16384).",
             "Правила: ratio — совпадение с эталоном (выше лучше); сек — общее время на письмо",
             "(ниже лучше); kw — доля ключевых мер эталона в ответе (если считается).",
             "Группировка — по эталонным типам (letter_types_gold.json), классификация моделей",
             "в оценке точности не учитывается.",
             "",
             "| id | тип | ratio 14B | ratio 9B | Δ | сек 14B | сек 9B | kw 14B | kw 9B |",
             "|----|-----|-----------|----------|-----|---------|--------|--------|-------|"]
    agg = {"r14": [], "r9": [], "s14": [], "s9": []}
    by = {}
    for i in ids:
        a14, a9 = num(r14.get(i), "ratio"), num(r9.get(i), "ratio")
        s14, s9 = num(r14.get(i), "elapsed_s"), num(r9.get(i), "elapsed_s")
        k14, k9 = num(r14.get(i), "kw_overlap"), num(r9.get(i), "kw_overlap")
        t = gold.get(i) or (r14.get(i) or r9.get(i)).get("letter_type") or "other"
        by.setdefault(t, {"r14": [], "r9": [], "s14": [], "s9": []})
        d = round(a9 - a14, 3) if (a14 is not None and a9 is not None) else None
        agg["r14"].append(a14) if a14 is not None else None
        agg["r9"].append(a9) if a9 is not None else None
        agg["s14"].append(s14) if s14 is not None else None
        agg["s9"].append(s9) if s9 is not None else None
        for k, v in (("r14", a14), ("r9", a9), ("s14", s14), ("s9", s9)):
            by[t][k].append(v) if v is not None else None
        dlt = "" if d is None else f"{'+' if d > 0 else ''}{d}"
        lines.append(f"| {i} | {t} | {fmt(a14)} | {fmt(a9)} | {dlt} | "
                     f"{fmt1(s14)} | {fmt1(s9)} | {fmt(k14)} | {fmt(k9)} |")

    lines += ["",
              "## Агрегаты по типам (avg ratio)",
              "",
              "| тип | 14B | 9B | Δ |",
              "|-----|-----|-----|-----|"]
    for t in ("hacker", "vulnerability", "compromise"):
        g = by.get(t, {})
        a14, a9 = avg(g.get("r14")), avg(g.get("r9"))
        lines.append(f"| {t} | {fmt(a14)} | {fmt(a9)} | "
                     f"{pct(a9, a14) or ('+' + str(round(a9 - a14, 3))) if (a14 is not None and a9 is not None) else ''} |")

    s14, s9 = agg["s14"], agg["s9"]
    lines += ["",
              "## Скорость (сек/письмо)",
              "",
              "| метрика | 14B | 9B | ускорение |",
              "|---------|-----|-----|-----------|",
              f"| avg | {fmt1(avg(s14))} | {fmt1(avg(s9))} | **×{round(avg(s14) / avg(s9), 2)}** |",
              f"| сумма | {fmt1(sum(v for v in s14 if v))} | {fmt1(sum(v for v in s9 if v))} | **×{round(sum(v for v in s14 if v) / sum(v for v in s9 if v), 2)}** |",
              f"| min | {fmt1(min(s14))} | {fmt1(min(s9))} | |",
              f"| max | {fmt1(max(s14))} | {fmt1(max(s9))} | |",
              "",
              "## Итог",
              "",
              f"- Качество (ratio): 14B **{avg(agg['r14'])}** vs 9B **{avg(agg['r9'])}**"
              f" — 14B выше на {round(100 * (avg(agg['r14']) - avg(agg['r9'])), 1)} п.п.",
              f"- Скорость: 9B в **×{round(avg(s14) / avg(s9), 2)} быстрее** "
              f"({fmt1(avg(s9))} с/письмо vs {fmt1(avg(s14))} с/письмо).",
              ""]

    out = q / "comparison_14b_vs_9b.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nComparison: {out}")
    print(json.dumps({"ratio_14b": avg(agg['r14']), "ratio_9b": avg(agg['r9']),
                      "sec_14b": avg(s14), "sec_9b": avg(s9),
                      "speedup": round(avg(s14) / avg(s9), 2),
                      "hacker_14b": avg(by.get('hacker', {}).get('r14')),
                      "hacker_9b": avg(by.get('hacker', {}).get('r9')),
                      "vuln_14b": avg(by.get('vulnerability', {}).get('r14')),
                      "vuln_9b": avg(by.get('vulnerability', {}).get('r9'))},
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()