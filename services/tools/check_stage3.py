#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 3 проверки: угрозы (threat-секции) на реальных письмах.

Для каждого кейса:
  - analyze_letter(main).threats -> число секций, group_name/theme/archive/exe/malware/measures
  - кросс-проверка полей первого пункта по «Проект мер …9-XX.docx» из папки письма:
    вхождение группировки/темы/имён в текст проекта мер.
Артефакт: data/quality/check_stage3.json
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.letter_analyzer import analyze_letter
from shared.parsers import parse_file


def _folder_text(root: Path, name: str, pattern: str) -> str:
    folder = root / name
    if not folder.is_dir():
        return ""
    for p in folder.iterdir():
        if (p.is_file() and re.search(pattern, p.name)
                and not p.name.startswith("Приложение")
                and str(p).lower().endswith(".docx")):
            try:
                res = parse_file(p)
                return (res.text or "").replace("\xa0", " ")
            except Exception as e:
                print(f"    parse {p.name}: {e}")
                return ""
    return ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--root", default=r"C:\Users\artyom\Desktop\лгту хуйня")
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage3.json"))
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    root = Path(args.root)

    rows = []
    total_sec = 0
    covered = 0
    t0_files = 0
    for n, c in corpus.items():
        info = analyze_letter(c["main"])
        threats = [{
            "number": t.number, "group_name": t.group_name, "theme": t.theme,
            "threat_type": t.threat_type, "archive_name": t.archive_name,
            "exe_name": t.exe_name, "malware_type": t.malware_type,
            "n_measures": len(t.measures),
            "first_measure": (t.measures[0][:140] if t.measures else ""),
        } for t in info.threats]
        total_sec += len(info.threats)

        proj = _folder_text(root, n, r"Проект")
        row = {"id": n, "letter_type": info.letter_type,
               "letter_number": info.letter_number, "letter_date": info.letter_date,
               "n_threats": len(info.threats), "threats_head": threats[:3]}
        if proj:
            proj_low = proj.lower()
            any_theme = True
            found_themes = [t["theme"] for t in threats if t["theme"]]
            if found_themes:
                any_theme = any(th.lower() in proj_low for th in found_themes)
            any_group = any(t["group_name"] and t["group_name"].lower() in proj_low
                            for t in threats if t["group_name"])
            n_meas_all = sum(t["n_measures"] for t in threats)
            meas_kw = ["не открывать", "не загружать", "песочни", "антивирус",
                       "обновление", "двухэтапн", "обучение", "карантин",
                       "блокировк", "фильтрац", "привилег", "минимизаци"]
            hits_kw = [k for k in meas_kw if k in proj_low]
            row["project_meer_chars"] = len(proj)
            row["project_meer_hits"] = {"any_theme": any_theme if found_themes else None,
                                        "any_group": any_group,
                                        "measures_keywords": hits_kw}
            hit = (any_theme if found_themes else True) or any_group
            t0_files += 1
            if hit:
                covered += 1
        rows.append(row)
        print(f"  {n:6} type={info.letter_type:10} threats={len(info.threats)} | "
              f"proj_hits={row.get('project_meer_hits', 'no-file')} (meas_kw={len(row.get('project_meer_hits',{}).get('measures_keywords',[]))})")
        for t in threats[:2]:
            print(f"      #{t['number']} grp={t['group_name']!r} theme={t['theme'][:60]!r} "
                  f"arch={t['archive_name']!r} exe={t['exe_name']!r} mw={t['malware_type']!r} "
                  f"meas={t['n_measures']}")

    report = {
        "stage": 3,
        "total_threat_sections": total_sec,
        "cases_with_project": t0_files,
        "cases_project_hit": covered,
        "rows": rows,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nThreat sections (all letters): {total_sec}; "
          f"project-hit {covered}/{t0_files}\nReport: {out}")


if __name__ == "__main__":
    main()