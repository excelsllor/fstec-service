#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сравнение E2E-прогонов Qwen3-8B vs Qwen3-14B.

Источники: check_e2e.json (актуальный, обычно 8B) и check_e2e_14b.json (бэкап 14B).
На выходе:
  - data/quality/report_YYYY-MM-DD_8b.md       (отчёт 8B в формате 14B-отчёта)
  - data/quality/comparison_14b_vs_8b.md       (построчное сравнение ratio + скорость)

Запуск (из services/):
    python -X utf8 tools/report_8b_vs_14b.py [check_8b.json] [check_14b.json]
"""
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def load(p: Path) -> dict:
    data = json.loads(Path(p).read_text(encoding="utf-8"))
    rows = {r["id"]: r for r in data.get("rows", [])}
    return rows


def ratio(r: dict | None):
    return r.get("ratio") if r else None


def sec(r: dict | None):
    return r.get("elapsed_s") if r else None


def kw(r: dict | None):
    return r.get("kw_overlap") if r else None


def avg(xs):
    xs = [x for x in xs if x is not None]
    return round(sum(xs) / len(xs), 3) if xs else None


def main():
    check_8b = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "quality" / "check_e2e.json"
    check_14b = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "data" / "quality" / "check_e2e_14b.json"
    rows8 = load(check_8b)
    rows14 = load(check_14b)

    ids = sorted(rows8.keys() | rows14.keys(), key=lambda i: int(i.split("-")[1]))
    order = {i: n for n, i in enumerate(ids)}
    types = {}
    for i in ids:
        t = (rows8.get(i) or rows14.get(i)).get("letter_type") or "other"
        types.setdefault(t, []).append(i)

    out8 = ["# Отчёт прогона e2e на Qwen3-8B (2026-09-17)",
            "",
            "Сборка: 22 письма (11 hacker, 1 compromise, 10 vulnerability), цепочка",
            "upload → parse → analyze (LLM vllm) → assess (BDU/NVD live) → reporting.",
            "Модель: Qwen3-8B-Q4_K_M (llama-server, Vulkan, порт 8001, ctx 16384).",
            "",
            "## Результаты (ratio к эталону, чем ближе к 1 — тем лучше)",
            "",
            "| id    | тип           | ratio | №/дата | kw        | сек  |",
            "|-------|---------------|-------|--------|-----------|------|"]
    comp = ["# Сравнение Qwen3-14B vs Qwen3-8B (E2E, 22 письма)",
            "",
            "Правила: ratio — совпадение с эталоном (выше лучше); сек — время на письмо",
            "(ниже лучше); kw — доля ключевых мер эталона в ответе.",
            "",
            "| id    | тип           | ratio 14B | ratio 8B | Δ | сек 14B | сек 8B | kw 14B | kw 8B |",
            "|-------|---------------|-----------|-----------|-----|---------|--------|--------|-------|"]
    agg = {"ratio_14": [], "ratio_8": [], "sec_14": [], "sec_8": []}
    by_type = {}
    for i in ids:
        r14, r8 = ratio(rows14.get(i)), ratio(rows8.get(i))
        s14, s8 = sec(rows14.get(i)), sec(rows8.get(i))
        t = (rows8.get(i) or rows14.get(i)).get("letter_type")
        by_type.setdefault(t, {"r14": [], "r8": [], "s14": [], "s8": []})
        d = r8 and r14 and round(r8 - r14, 3)
        agg["ratio_14"].append(r14) if r14 is not None else None
        agg["ratio_8"].append(r8) if r8 is not None else None
        agg["sec_14"].append(s14) if s14 is not None else None
        agg["sec_8"].append(s8) if s8 is not None else None
        by_type[t]["r14"].append(r14) if r14 is not None else None
        by_type[t]["r8"].append(r8) if r8 is not None else None
        by_type[t]["s14"].append(s14) if s14 is not None else None
        by_type[t]["s8"].append(s8) if s8 is not None else None
        r8s = f"{r8}" if r8 is not None else "-"
        k8 = kw(rows8.get(i)) or "-"
        s8s = f"{s8}" if s8 is not None else "-"
        out8.append(f"| {i} | {t} | {r8s} | 1/1 | {k8} | {s8s} |")
        comp.append(f"| {i} | {t} | {r14 or '-'} | {r8s} | "
                    f"{('+' if d and d > 0 else '') if d is not None else 0} | "
                    f"{s14 or '-'} | {s8s} | {kw(rows14.get(i)) or '-'} | {k8} |")

    r8_avg = avg(agg["ratio_8"])
    r14_avg = avg(agg["ratio_14"])
    out8 += ["",
             "## Агрегаты 8B",
             "",
             f"- hacker: avg **{avg(by_type.get('hacker', {}).get('r8'))}**; "
             f"vulnerability: avg **{avg(by_type.get('vulnerability', {}).get('r8'))}**; "
             f"compromise: **{avg(by_type.get('compromise', {}).get('r8'))}**.",
             f"- Все 22: avg **{r8_avg}**.",
             f"- Время: сумма **{sum(x for x in agg['sec_8'] if x)} с**, "
             f"avg **{avg(agg['sec_8'])} с/письмо**, "
             f"min **{min(agg['sec_8'])}**, max **{max(agg['sec_8'])}**.",
             ""]
    comp += ["",
             "## Агрегаты",
             "",
             "| метрика        | 14B | 8B |",
             "|----------------|-----|-----|",
             f"| hacker avg ratio | {avg(by_type.get('hacker', {}).get('r14'))} | "
             f"{avg(by_type.get('hacker', {}).get('r8'))} |",
             f"| vulnerability avg ratio | {avg(by_type.get('vulnerability', {}).get('r14'))} | "
             f"{avg(by_type.get('vulnerability', {}).get('r8'))} |",
             f"| compromise ratio | {avg(by_type.get('compromise', {}).get('r14'))} | "
             f"{avg(by_type.get('compromise', {}).get('r8'))} |",
             f"| Все avg ratio | {r14_avg} | {r8_avg} |",
             f"| Все сек/письмо | {avg(agg['sec_14'])} | {avg(agg['sec_8'])} |",
             f"| Сумма, сек | {sum(x for x in agg['sec_14'] if x)} | {sum(x for x in agg['sec_8'] if x)} |",
             ""]

    out_path = ROOT / "data" / "quality" / f"report_{date.today().isoformat()}_8b.md"
    cmp_path = ROOT / "data" / "quality" / "comparison_14b_vs_8b.md"
    out_path.write_text("\n".join(out8), encoding="utf-8")
    cmp_path.write_text("\n".join(comp), encoding="utf-8")
    print(f"\nReport 8B:  {out_path}")
    print(f"Compare:    {cmp_path}")
    print(json.dumps({"hacker_14b": avg(by_type.get('hacker', {}).get('r14')),
                      "hacker_8b": avg(by_type.get('hacker', {}).get('r8')),
                      "vuln_14b": avg(by_type.get('vulnerability', {}).get('r14')),
                      "vuln_8b": avg(by_type.get('vulnerability', {}).get('r8')),
                      "all_14b": r14_avg, "all_8b": r8_avg,
                      "sec_14b": avg(agg['sec_14']), "sec_8b": avg(agg['sec_8'])},
                     ensure_ascii=False, indent=1))


if __name__ == "__main__":
    main()