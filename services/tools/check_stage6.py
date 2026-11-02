#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Стадия 6 проверки: SLA/routing (ТЗ 3.3) по письмам корпуса + синтетический vuln-кейс.

Таблица sla/routing для писем с BDU/CVE-упоминаниями (mock-CMDB, enrich=False),
и для синтетического vulnerability-кейса с живыми NVD/BDU (enrich=True).
Артефакт: data/quality/check_stage6.json
"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.extractor.vuln_extractor import extract_vulns
from security_service.assessment import assess_document
from security_service.cmdb import InventoryItem


class MockCMDB:
    def __init__(self, products: dict[str, str]):
        self._products = products
        self.queries = []

    async def find_many(self, product: str) -> list[InventoryItem]:
        self.queries.append(product)
        name, ver = None, ""
        for key, version in self._products.items():
            if key.lower() in (product or "").lower():
                name, ver = key, version
                break
        if not name:
            return []
        return [InventoryItem(name=name, vendor="mock", version=ver,
                              cpe=f"cpe:2.3:a:mock:{name}:{ver}:*:*:*:*:*:*:*")]


def _to_raw(vulns) -> list[dict]:
    return [{"bdu_id": v.bdu_id, "cve_id": v.cve_id, "software": v.software,
             "severity": v.severity, "description": v.description} for v in vulns]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    ap.add_argument("--synthetic", default=str(ROOT / "data" / "quality" / "synthetic" / "vulnerability_1.txt"))
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "check_stage6.json"))
    args = ap.parse_args()
    corpus = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
    inventory = {"Microsoft Office": "14.0.0",
                 "XZ Utils": "5.6.0",
                 "Cisco Catalyst SD-WAN Controller": "20.12.1"}
    cmdb = MockCMDB(inventory)

    print("=== 6a: таблица SLA/routing по real-письмам (enrich=False) ===")
    rows = []
    for n, c in corpus.items():
        raw = _to_raw(extract_vulns(c["main"]))
        if not raw:
            rows.append({"id": n, "letter_type": c["gold"]["classification"], "vulns": 0,
                         "sla": "n/a", "routing": "n/a"})
            print(f"  {n:6} {c['gold']['classification']:10} vulns=0  sla=n/a")
            continue
        out = asyncio.run(assess_document(raw, cmdb=cmdb, enrich=False))
        rows.append({"id": n, "letter_type": c["gold"]["classification"], "vulns": len(raw),
                     "sla": out.sla, "routing": out.routing,
                     "cmdb_matches": [a["software"] for a in out.assessed if a["cmdb_match"]]})
        print(f"  {n:6} {c['gold']['classification']:10} vulns={len(raw)}  "
              f"sla={out.sla} routing={out.routing} matched={[a['software'] for a in out.assessed if a['cmdb_match']]}")

    print("\n=== 6b: synthetic vulnerability-кейс (enrich=True, живой NVD/BDU) ===")
    synth = _to_raw(extract_vulns(Path(args.synthetic).read_text(encoding="utf-8")))
    from security_service.nvd_client import NVDClient
    from security_service.bdu_client import BDUClient
    out = asyncio.run(assess_document(synth, cmdb=cmdb, enrich=True,
                                      nvd=NVDClient(), bdu=BDUClient()))
    for a in out.assessed:
        print(f"     {a['bdu_id'] or a['cve_id']} soft={a['software']!r:45} sev={a['severity']:9} "
              f"match={a['cmdb_match']} -> {a['recommendation']}")
    print(f"  sla={out.sla} routing={out.routing} external_errors={out.external_errors}")

    report = {"stage": 6, "table": rows, "synthetic": {
        "sla": out.sla, "routing": out.routing,
        "external_errors": out.external_errors,
        "assessed": out.assessed,
        "cmdb_queries": cmdb.queries}}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"\nReport: {args.out}")


if __name__ == "__main__":
    main()