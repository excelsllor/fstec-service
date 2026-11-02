#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 5 проверки: уязвимости.

  a) extract_vulns на 12 реальных письмах — ожидаем 0 уязвимостей (нет ложных).
  b) синтетический vulnerability-кейс (data/quality/synthetic/vulnerability_1.txt)
     — BDU:2021-05969 / CVE-2024-3094: ПО, уровень, CVSS, фикс-версия.
  c) live BDU (bdu.fstec.ru/vul/print/{id}) и live NVD (services.nvd.nist.gov) —
     наполнение EnrichedVuln; при TLS/сетевом сбое фиксируем external_error.
Артефакт: data/quality/check_stage5.json
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.vuln_extractor import extract_vulns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--synthetic", default=str(ROOT / "data" / "quality" / "synthetic" / "vulnerability_1.txt"))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage5.json"))
    args = ap.parse_args()

    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    print("=== 5a: extract_vulns по 12 письмам ===")
    real = {}
    false_pos = 0
    for n, c in corpus.items():
        vulns = extract_vulns(c["main"])
        real[n] = [v.bdu_id or v.cve_id for v in vulns]
        false_pos += len(vulns)
        marker = "OK" if not vulns else "FP!"
        print(f"  {n:6} vulns={len(vulns)} {marker}")
    print(f"  false positives: {false_pos}")

    print("\n=== 5b: синтетический vulnerability-кейс ===")
    synth_text = Path(args.synthetic).read_text(encoding="utf-8")
    sv = extract_vulns(synth_text)
    as_dict = [{"bdu": v.bdu_id, "cve": v.cve_id, "software": v.software,
                "severity": v.severity, "desc": v.description[:160]} for v in sv]
    for v in sv:
        print(f"  {v.bdu_id or v.cve_id} soft={v.software!r} sev={v.severity} "
              f"desc={v.description[:120]!r}")

    print("\n=== 5c: live BDU + NVD ===")
    live = {"bdu": None, "nvd": None, "errors": []}
    async def _live():
        from security_service.bdu_client import BDUClient
        from security_service.nvd_client import NVDClient
        bdu = BDUClient()  # base_url=https://bdu.fstec.ru
        try:
            obj = await bdu.get_bdu("2021-05969")
            live["bdu"] = obj.normalize() if obj else None
        except Exception as e:
            live["errors"].append(f"bdu: {type(e).__name__}: {e}")
        nvd = NVDClient()
        try:
            obj = await nvd.get_cve("CVE-2024-3094")
            live["nvd"] = obj.normalize() if obj else None
        except Exception as e:
            live["errors"].append(f"nvd: {type(e).__name__}: {e}")
    asyncio.run(_live())
    if live["bdu"]:
        b = live["bdu"]
        print(f"  BDU: id={b['bdu_id']} title={b['title'][:80]!r} sev={b['severity']} "
              f"cvss={b['cvss_score'] or b.get('cvss_base_score') or ''} fixed={b.get('fixed_version')!r}")
    else:
        print(f"  BDU: None ({live['errors'] if live['errors'] else 'нет данных'})")
    if live["nvd"]:
        n = live["nvd"]
        print(f"  NVD: {n['cve_id']} sev={n['severity']} "
              f"cvss={n.get('cvss_base_score') or n.get('cvss_score')} fixed={n.get('fixed_version')!r}")
    else:
        print(f"  NVD: None ({live['errors'] if live['errors'] else 'нет данных'})")

    report = {
        "stage": 5,
        "real_letters": real,
        "false_positives": false_pos,
        "synthetic": as_dict,
        "live": live,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {out}")


if __name__ == "__main__":
    main()