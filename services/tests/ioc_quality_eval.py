"""Offline precision/recall eval for IP/email/domain extraction.

Run: python tests/ioc_quality_eval.py
The corpus is synthetic but deliberately dirty: defanged values, line breaks,
file names, versions and internal addresses are mixed with real indicators.
"""
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from shared.extractor.ioc_extractor import extract_iocs  # noqa: E402


def _case(rng, i):
    ip = f"198.51.100.{i % 250 + 1}"
    cidr = f"203.0.113.{(i * 7) % 250}/24"
    domain = f"host{i}.example{i % 7}.com"
    email = f"user+tag{i}@mail{i % 5}.example.org"
    text = (
        f"Вложение report{i}.pdf, версия {i % 9}.{i % 5}.{i % 3}, тел. +7 (900) 123-45-67. "
        f"IP: {ip}; сеть {cidr}; e-mail: {email}; домен {domain}. "
        f"Дополнительно: bad[.]host[.]net, {i}.jpg, 1.2.3.4.5"
    )
    expected_ips = {ip}
    expected_domains = {domain, f"mail{i % 5}.example.org", "bad.host.net"}
    expected_emails = {email}
    return text, expected_ips, expected_domains, expected_emails


def main():
    rng = random.Random(20261027)
    cases = [_case(rng, i) for i in range(1, 101)]
    tp = {"ip": 0, "domain": 0, "email": 0}
    fp = {"ip": 0, "domain": 0, "email": 0}
    fn = {"ip": 0, "domain": 0, "email": 0}
    for text, eips, edomains, eemails in cases:
        r = extract_iocs(text)
        got = {"ip": set(r.ips), "domain": set(r.domains), "email": set(r.emails)}
        exp = {"ip": eips, "domain": edomains, "email": eemails}
        for typ in tp:
            tp[typ] += len(got[typ] & exp[typ])
            fp[typ] += len(got[typ] - exp[typ])
            fn[typ] += len(exp[typ] - got[typ])
    print("n", len(cases))
    for typ in tp:
        denom = tp[typ] + fp[typ]
        recall_den = tp[typ] + fn[typ]
        precision = 100 * tp[typ] / denom if denom else 100
        recall = 100 * tp[typ] / recall_den if recall_den else 100
        print(f"{typ}: tp={tp[typ]} fp={fp[typ]} fn={fn[typ]} "
              f"precision={precision:.3f}% recall={recall:.3f}%")
    total_tp = sum(tp.values())
    total_fp = sum(fp.values())
    total_fn = sum(fn.values())
    p = 100 * total_tp / (total_tp + total_fp) if total_tp + total_fp else 100
    r = 100 * total_tp / (total_tp + total_fn) if total_tp + total_fn else 100
    print(f"overall: precision={p:.3f}% recall={r:.3f}%")
    return 0 if p >= 99 and r >= 99 else 1


if __name__ == "__main__":
    raise SystemExit(main())
