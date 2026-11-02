#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сравнение сгенерированного ответа (ТЗ 2.5.2) с эталонами «Ответ  на письмо 9-XX.docx».

Для 12 писем: генерируем проект ответа тем же кодом, что и в стадии 7,
сверяем с эталоном (папка кейса и generated_otvety):
  - реквизиты (номер/дата), тема (LLM-поле), смысловое совпадение,
  - доли ключевых мер, дифф-расхождения (фразы эталона и наши доп. фразы).
Артефакты: data/quality/compare_reply.json + docs/reply_diff_report.md
"""
import difflib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.letter_analyzer import analyze_letter
from shared.generator.response_generator import generate_reply_text
from shared.parsers import parse_file

MEASURE_KEYWORDS = [
    "вложени", "открывать", "загружать", "url", "фишинг", "песочниц", "sandbox",
    "антивирус", "учетных записей", "привилегиями", "домен", "ограничение обращений",
    "мониторинг", "инструктаж", "сертифицированн", "вредоносн",
]
NORM = re.compile(r"[^а-яёa-z0-9 ]+")


def norm(s: str) -> str:
    return NORM.sub(" ", s.lower())
WORD = re.compile(r"[а-яёa-z0-9]+")


def phrases(src: str) -> list[str]:
    return [f"{a} {b} {c}" for a, b, c in zip(src, src[1:], src[2:]) if len(a) > 1]


def diff_runs(a_words: list[str], b_words: list[str], wmin: int = 3):
    sm = difflib.SequenceMatcher(a=a_words, b=b_words, autojunk=False)
    missing, extra = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        chunk = " ".join(a_words[i1:i2]).strip()
        if tag in ("delete", "replace") and len(a_words[i1:i2]) >= wmin:
            missing.append(chunk)
        if tag in ("insert", "replace"):
            chunk_b = " ".join(b_words[j1:j2]).strip()
            if len(b_words[j1:j2]) >= wmin:
                extra.append(chunk_b)
    return missing[:8], extra[:8]


def ref_sections(text: str) -> list[str]:
    """Нумерованные содержательные блоки эталона (пункты с мерами)."""
    secs = []
    for m in re.finditer(r"(?m)^\s*(\d{1,2})\s*\.\s*?", text):
        secs.append(f"{m.group(1)}. " + " ".join(text[m.end():].strip().split()[:8]))
    return secs


def grab_quoted(text: str) -> list[str]:
    text = re.sub(r"[«»\"“”]", "«»", text)
    return [g for g in re.findall(r"«([^»]{3,80})»", text)]


def main():
    root = Path(r"C:\Users\artyom\Desktop\лгту хуйня")
    corpus = json.loads((ROOT / "data" / "quality" / "corpus_index.json").read_text(encoding="utf-8"))
    out = ROOT / "data" / "quality" / "compare_reply.json"
    md_path = ROOT / "docs" / "reply_diff_report.md"

    rows, md = [], ["# Сравнение сгенерированного ответа с эталоном (9-XX)", ""]
    for n in sorted(corpus):
        c = corpus[n]
        info = analyze_letter(c["main"])
        threats = [{"number": t.number, "threat_type": t.threat_type, "theme": t.theme,
                    "description": t.description} for t in info.threats]
        reply = generate_reply_text(
            letter_number=info.letter_number, letter_date=info.letter_date,
            letter_type=info.letter_type, threats=threats, vulnerabilities=[], addr_count=1)
        theme = threats[0]["theme"] if threats else ""

        refs = []
        for base in (root, root / "generated_otvety"):
            for p in (base / n).glob("*") if (base / n).is_dir() else [base / f"Ответ на письмо {n}.docx"]:
                if p.suffix.lower() == ".docx" and "Ответ" in p.name:
                    refs.append((str(p), (parse_file(p).text or "")))
        if not refs:
            continue

        r = refs[0]
        ref_n, ref_t = r[0], r[1]
        ref_norm = norm(ref_t)
        reply_norm = norm(reply)

        def tok(s: str) -> str:
            return " ".join(word_list(s.lower()))

        num_ok = info.letter_number and tok(info.letter_number) in ref_norm
        date_ok = bool(info.letter_date)
        if date_ok:
            d = info.letter_date
            cands = [tok(d)]
            if re.fullmatch(r"\d{4}-\d{2}-\d{2}", d):
                cands.append(tok(f"{d[8:10]}.{d[5:7]}.{d[0:4]}"))
            date_ok = any(c in ref_norm for c in cands)
        theme_ok = (theme.lower().strip() != "") and theme.lower() in ref_norm
        kw_hit = [k for k in MEASURE_KEYWORDS if k in ref_norm]
        kw_miss = [k for k in kw_hit if k not in reply_norm]
        ratio = round(difflib.SequenceMatcher(None, reply_norm.split(), ref_norm.split()).ratio(), 3)

        ref_words = word_list(ref_norm)
        reply_words = word_list(reply_norm)
        missing, extra = diff_runs(ref_words, reply_words, 4)

        ref_themes = grab_quoted(ref_t)
        threat_themes = [t.theme for t in info.threats if t.theme]
        covered = [tt for tt in threat_themes if any(tt.lower() in q.lower() for q in ref_themes)]
        summary = re.sub(r"\s+", " ", c["main"].strip())[:120]
        rows.append({"id": n, "letter_number": info.letter_number, "date": info.letter_date,
                     "type": info.letter_type, "n_threats": len(threats), "theme": theme,
                     "reference_file": Path(ref_n).name, "ref_chars": len(ref_t), "reply_chars": len(reply),
                     "header_num_ok": num_ok, "header_date_ok": date_ok, "theme_in_ref": theme_ok,
                     "threat_themes": threat_themes, "threats_covered_in_ref": covered,
                     "ref_sections": ref_sections(ref_t),
                     "kwargs_total": len(kw_hit), "kwargs_overlap": len(kw_hit) - len(kw_miss),
                     "ratio": ratio, "missing_phrases": missing, "extra_phrases": extra})

        print(f"=== {n} [{info.letter_number}/{info.letter_date}] {info.letter_type} "
              f"theme='{theme}' ratio={ratio} kw={len(kw_hit)-len(kw_miss)}/{len(kw_hit)} "
              f"num={num_ok} date={date_ok} theme_ref={theme_ok} "
              f"threats={len(threat_themes)} covered={len(covered)}/{len(threat_themes)} "
              f"ref_sections={len(ref_sections(ref_t))}")
        for m in missing:
            print(f"    missing: {m}")
        for e in extra:
            print(f"    extra  : {e}")

        md.append(f"## {n} — {info.letter_number} от {info.letter_date} ({info.letter_type})")
        md.append(f"- Тема (LLM/extractor): «{theme}» — в эталоне: **{'да' if theme_ok else 'НЕТ'}**; "
                  f"реквизиты: номер **{'ok' if num_ok else 'NO'}** / дата **{'ok' if date_ok else 'NO'}**")
        md.append(f"- Структура эталона: {len(ref_sections(ref_t))} нумерованных блоков; наши угрозы покрыты "
                  f"**{len(covered)}/{len(threat_themes)}** (темы: {', '.join(threat_themes) or '—'})")
        md.append(f"- Совпадение текста (difflib): `{ratio}`; ключевые меры эталона покрыты "
                  f"**{len(kw_hit) - len(kw_miss)}/{len(kw_hit)}** (не покрыто: {', '.join(kw_miss) or '—'})")
        if missing:
            md.append(f"- Расхождения — есть в эталоне, нет в нашем ответе:\n  - " +
                      "\n  - ".join(f"«{x}»" for x in missing))
        if extra:
            md.append(f"- Расхождения — есть в нашем ответе, нет в эталоне:\n  - " +
                      "\n  - ".join(f"«{x}»" for x in extra))
        md.append("")

    report = {"stage": "reply_vs_etalon", "cases": rows}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("\n".join(md), encoding="utf-8")
    print(f"\nReport: {out}\nMarkdown: {md_path}")


def word_list(s: str) -> list[str]:
    return WORD.findall(s)


if __name__ == "__main__":
    main()