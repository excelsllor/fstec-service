#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 7 проверки: сборка артефактов (ТЗ 2.5.1 карточка + 2.5.2 проект ответа).

Для писем 9-104/9-77/9-89:
  - build_indicator_card(docx) и generate_reply_text -> render_reply_docx(docx)
  - сверка с эталонами: «Ответ  на письмо 9-XX.docx» из папки кейса и generated_otvety
Артефакты: data/quality/artifacts/…  ;  отчёт check_stage7.json
"""
import argparse
import json
import re
import sys
from io import BytesIO
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from docx import Document
from shared.config import ORG_NAME
from shared.extractor.ioc_extractor import extract_iocs
from shared.extractor.letter_analyzer import analyze_letter
from shared.extractor.vuln_extractor import extract_vulns
from shared.generator.indicator_card import build_indicator_card
from shared.generator.response_generator import generate_reply_text, render_reply_docx
from shared.parsers import parse_file

CASES = ["9-104", "9-77", "9-89"]


def _docx_text(data: bytes) -> str:
    return "\n".join(p.text for p in Document(BytesIO(data)).paragraphs)


def _reference(root: Path, name: str, src_dir: Path, fallback_dir: Path) -> list[tuple[str, str]]:
    texts = []
    for where in (src_dir, fallback_dir):
        for p in (root / where / name).glob("*"):
            if p.is_file() and "Ответ" in p.name and p.suffix.lower() == ".docx":
                try:
                    texts.append((str(p), (parse_file(p).text or "")))
                except Exception as e:
                    texts.append((str(p), f"ERR: {e}"))
    return texts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--root", default=r"C:\Users\artyom\Desktop\лгту хуйня")
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage7.json"))
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    root = Path(args.root)
    arts = ROOT / "data" / "quality" / "artifacts"
    arts.mkdir(parents=True, exist_ok=True)

    rows = []
    for n in CASES:
        c = corpus[n]
        main = c["main"]
        full = c.get("full") or main
        info = analyze_letter(main)
        threats = [{"number": t.number, "threat_type": t.threat_type,
                    "theme": t.theme, "description": t.description} for t in info.threats]
        ioc = extract_iocs(full)
        vulns = [{"bdu_id": v.bdu_id, "cve_id": v.cve_id, "software": v.software,
                  "severity": v.severity, "description": v.description,
                  "fixed_version": ""} for v in extract_vulns(full)]

        ips = sorted(ioc.ips)
        domains = sorted(ioc.domains)
        emails = sorted(ioc.emails)
        addr_count = max(1, len(ips) + len(domains))

        card = build_indicator_card(
            org_name=ORG_NAME,
            source_filename=f"{n}.pdf",
            document_id=1000 + int(n.split("-")[1]),
            ips=ips, ipv6=[], domains=domains, emails=emails,
            vulnerabilities=vulns, sla="normal")
        card_path = arts / f"card_{n}.docx"
        card_path.write_bytes(card)

        reply = generate_reply_text(
            letter_number=info.letter_number, letter_date=info.letter_date,
            letter_type=info.letter_type, threats=threats,
            vulnerabilities=vulns, addr_count=addr_count)
        reply_path = arts / f"reply_{n}.docx"
        reply_path.write_bytes(render_reply_docx(reply))
        (arts / f"reply_{n}.txt").write_text(reply, encoding="utf-8")

        refs = _reference(root, n, root, root / "generated_otvety")
        ref_matches = []
        for src, rt in refs:
            rt_low = rt.lower()
            ref_matches.append({
                "file": src,
                "has_header": (info.letter_number or "") in rt,
                "has_measures": any(k in rt_low for k in ("не открывать", "не загружать",
                                                          "песочниц", "принят", "меры", "обновлен")),
                "len": len(rt)})
        row = {
            "id": n,
            "letter_number": info.letter_number,
            "letter_date": info.letter_date,
            "letter_type": info.letter_type,
            "n_threats": len(threats),
            "ips": len(ips), "domains": len(domains), "emails": len(emails),
            "reply_head": reply.splitlines()[:2],
            "card_head": _docx_text(card).splitlines()[:2],
            "reply_chars": len(reply),
            "references": ref_matches,
            "artifacts": {"card": str(card_path), "reply": str(reply_path)},
        }
        rows.append(row)
        print(f"=== {n} {info.letter_type} [{info.letter_number} от {info.letter_date}] "
              f"thr={len(threats)} ip={len(ips)} dom={len(domains)} em={len(emails)}")
        print("  reply head:", reply.splitlines()[0])
        print("  reply body:", "  ".join(reply.splitlines()[3:6]))
        for r in ref_matches:
            print(f"  ref {Path(r['file']).name}: header={r['has_header']} measures={r['has_measures']} len={r['len']}")

    report = {"stage": 7, "cases": rows}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {args.out}")


if __name__ == "__main__":
    main()