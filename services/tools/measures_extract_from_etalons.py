#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Покрытие библиотеки мер (data/generator/measures_library.json) эталонами 9-XX.

Для каждого из 12 писем:
  - извлекаем меры (строки «  ...») и заголовки блоков из эталонного docx;
  - находим ближайшую меру библиотеки (SequenceMatcher);
  - отчёт: доля покрытых мер, пробелы (меры эталона без близкого аналога),
    интро-фразы блоков vs intro_fragments.
Артефакты: data/quality/measures_library_coverage.json, docs/measures_library_coverage.md
"""
import difflib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.parsers import parse_file  # noqa: E402

MEASURE_RE = re.compile(r"^\s{2,}\S.*;?\s*$")
BLOCK_RE = re.compile(r"^\s*(?:\d{1,2}\.)?\s*В целях предотвращения", re.IGNORECASE)
NON_MEASURE_RE = re.compile(
    r"^(Ответ на письмо|Сообщаем о принятых|С уважением|Ответственное должностное"
    r"|Выявлены уязвимости|Требуется срочно|обновить )",
    re.IGNORECASE)
INTRO_RE = re.compile(r"связанных с\s+(.+?),\s*приняты следующие меры защиты", re.IGNORECASE | re.DOTALL)
NORM_RE = re.compile(r"[^а-яёa-z0-9 ]+")


def norm(s: str) -> str:
    return " ".join(NORM_RE.sub(" ", s.lower()).split())


def extract_measures(text: str) -> tuple[list[str], list[str], list[str]]:
    """(заголовки блоков, интро-фразы, меры) из текста эталона."""
    headers, intros, measures = [], [], []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if BLOCK_RE.match(line):
            headers.append(line)
            m = INTRO_RE.search(line)
            if m:
                intros.append(" ".join(m.group(1).split()))
            continue
        if not NON_MEASURE_RE.match(line) and len(line) > 25:
            measures.append(line)
    return headers, intros, measures


def best_match(measure: str, library: list[str], th: float = 0.55) -> tuple[str, float]:
    m = max(library, key=lambda t: difflib.SequenceMatcher(None, norm(t), norm(measure)).ratio())
    return m, difflib.SequenceMatcher(None, norm(m), norm(measure)).ratio()


def main():
    root = Path(r"C:\Users\artyom\Desktop\лгту хуйня")
    corpus = json.loads((ROOT / "data" / "quality" / "corpus_index.json").read_text(encoding="utf-8"))
    lib_file = ROOT / "data" / "generator" / "measures_library.json"
    frag_file = ROOT / "data" / "generator" / "intro_fragments.json"
    library = [m["text"] for m in json.loads(lib_file.read_text(encoding="utf-8"))]
    norm_lib = [norm(t) for t in library]
    fragments = json.loads(frag_file.read_text(encoding="utf-8"))
    frag_by_key = {f["key"]: f["template"] for f in fragments}

    rows, md = [], ["# Покрытие библиотеки мер эталонами (9-XX)", "",
                    f"Библиотека: {len(library)} мер, {len(fragments)} интро-фрагментов.", ""]
    all_gaps: dict[str, int] = {}
    total = covered = 0
    for n in sorted(corpus):
        refs = []
        for base in (root, root / "generated_otvety"):
            base_dir = base / n
            paths = list(base_dir.glob("*Ответ*.docx")) if base_dir.is_dir() \
                else [base / f"Ответ на письмо {n}.docx"]
            for p in paths:
                if p.suffix.lower() == ".docx" and "Ответ" in p.name:
                    refs.append(parse_file(p).text or "")
        if not refs:
            continue
        headers, intros, measures = extract_measures(refs[0])
        best, gaps, miss = [], [], []
        for mea in measures:
            total += 1
            _, r = best_match(mea, library)
            if r >= 0.55:
                covered += 1
            else:
                gaps.append((mea, round(r, 3)))
                all_gaps[mea] = round(r, 3)
        intro_hits = []
        for it in intros:
            nit = norm(it)
            hit = next((f"{k} ({round(difflib.SequenceMatcher(None, nit, norm(frag_by_key[k])).ratio(), 2)})"
                        for k in frag_by_key
                        if difflib.SequenceMatcher(None, nit, norm(frag_by_key[k])).ratio() >= 0.45), None)
            intro_hits.append((it, hit))
        rows.append({"id": n, "blocks": len(headers), "measures_total": len(measures),
                     "covered": len(measures) - len(gaps), "gaps": gaps, "intros": intros,
                     "intro_hits": intro_hits})
        pct = round(100 * (len(measures) - len(gaps)) / max(len(measures), 1))
        md.append(f"## {n} — блоков {len(headers)}, мер {len(measures)} — покрыто "
                  f"**{len(measures) - len(gaps)}/{len(measures)} ({pct}%)**")
        for it, hit in intro_hits:
            md.append(f"- интро: «{it[:90]}» — {'OK: ' + hit if hit else 'НЕТ фрагмента'}")
        for g, r in gaps:
            md.append(f"- пробел ({r}): {g}")
        md.append("")

    md.append(f"## Итого\n\nПокрытие мер: **{covered}/{total}** "
              f"({round(100 * covered / max(total, 1))}%).\n")
    if all_gaps:
        md.append("### Пробелы библиотеки (нет близкого аналога):")
        for t, r in sorted(all_gaps.items(), key=lambda kv: kv[1]):
            md.append(f"- [{r:.2f}] {t}")
    out = ROOT / "data" / "quality" / "measures_library_coverage.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"stage": "measures_library_vs_etalons",
                               "library_size": len(library), "measures_total": total,
                               "covered": covered, "cases": rows}, ensure_ascii=False, indent=1),
                   encoding="utf-8")
    md_path = ROOT / "docs" / "measures_library_coverage.md"
    md_path.write_text("\n".join(md), encoding="utf-8")
    print(f"Coverage: {covered}/{total} ({round(100 * covered / max(total, 1))}%)")
    print(f"Report: {out}\nMarkdown: {md_path}")


if __name__ == "__main__":
    main()