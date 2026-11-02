"""Assessment (ТЗ 2.4): keep-all, версионный match, source, SLA-эскалация, рекомендация,
external_errors, вывод fixed_version по регексу."""
import asyncio

from security_service.assessment import assess_document
from security_service.cmdb_mock import MockCMDB
from security_service.enriched import CpeMatch, EnrichedVuln, RangeSpec
from tests.fakes import (BDU_ENRICHED, NVD_CRITICAL, VULN_RAW, FakeBDUClient,
                         FakeNVDClient)


async def _assess(vulns, nvd=None, bdu=None, cmdb=None, enrich=True):
    return await assess_document(vulns, cmdb=cmdb or MockCMDB(),
                                 enrich=enrich, nvd=nvd, bdu=bdu)


def test_keep_all_and_match():
    raw = dict(VULN_RAW)
    raw["cve_id"] = ""
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(None), bdu=FakeBDUClient(BDU_ENRICHED)))
    assert len(ass.assessed) == 1
    a = ass.assessed[0]
    assert a["cmdb_match"] is True                 # Log4j 2.15.0 в уязвимом диапазоне/продукт
    assert a["current_version"] == "2.15.0"
    assert a["target_version"] == "2.17.0"         # fixed_version из BDU
    assert a["source"] == "bdu"
    assert a["severity"] == "critical"
    assert "с 2.15.0 до 2.17.0" in a["recommendation"]


def test_bdu_is_authoritative_for_cvss_and_severity():
    nvd = EnrichedVuln(source="nvd", cve_id="CVE-2026-0001", severity="high",
                       cvss_version="2.0", cvss_score=10.0)
    bdu = EnrichedVuln(source="bdu", bdu_id="BDU:2026-0001", cve_id="CVE-2026-0001",
                       severity="critical", cvss_version="3.1", cvss_score=8.8)
    raw = {"bdu_id": "BDU:2026-0001", "cve_id": "CVE-2026-0001",
           "description": "Уязвимость тест", "software": "Test", "severity": "unknown"}
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(nvd), bdu=FakeBDUClient(bdu)))
    a = ass.assessed[0]
    assert a["source"] == "bdu"
    assert a["severity"] == "critical"
    assert a["cvss_version"] == "3.1"


def test_no_match_kept():
    raw = {"cve_id": "CVE-2026-0001", "bdu_id": "", "description": "CVE без ПO",
           "software": "Неведомый софт", "severity": "critical"}
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(None), bdu=FakeBDUClient(None)))
    assert len(ass.assessed) == 1                     # keep-all: no-match НЕ выбрасывается
    a = ass.assessed[0]
    assert a["cmdb_match"] is False
    assert a["current_version"] == ""
    assert a["source"] == "manual"


def test_sla_escalation_on_match():
    no_match = {"cve_id": "", "bdu_id": "", "description": "", "software": "Foo",
                "severity": "low"}
    ass = asyncio.run(_assess([no_match], nvd=None, bdu=None))
    assert ass.sla == "normal" and ass.routing == "default"
    ass2 = asyncio.run(_assess([dict(VULN_RAW)], nvd=FakeNVDClient(NVD_CRITICAL),
                               bdu=FakeBDUClient()))
    assert ass2.sla == "critical" and ass2.routing == "infosec"


def test_range_does_not_match():
    """OpenSSL 1.1.1k в инвентаре, но диапазон CVE = >=3.0 → no match."""
    openssl = {
        "cve_id": "CVE-2026-9999", "bdu_id": "", "description": "OpenSSL >=3.0",
        "software": "OpenSSL", "severity": "high",
    }
    nvd_openssl = EnrichedVuln(
        source="nvd", cve_id="CVE-2026-9999", severity="high", cvss_score=7.5,
        cpe_matches=[CpeMatch(criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                              ranges=[RangeSpec(min_version="3.0", min_inclusive=True, raw=">=3.0")])],
    )
    ass = asyncio.run(_assess([openssl], nvd=FakeNVDClient(nvd_openssl), bdu=FakeBDUClient(None)))
    a = ass.assessed[0]
    assert a["cmdb_match"] is False                  # 1.1.1k < 3.0 (вне диапазона)
    assert a["current_version"] == "1.1.1k"
    assert a["is_applicable"] is True
    assert a["action_type"] == "skip"


def test_external_errors_collected():
    raw = dict(VULN_RAW)
    raw["bdu_id"] = ""
    ass = asyncio.run(_assess([raw], nvd=FakeNVDClient(fail=True), bdu=FakeBDUClient()))
    assert ass.external_errors                     # NVD недоступен → ошибка записана
    # BDU-обогащение не вызывалось (cve_id первым, но упал) — raw-дубль остаётся, keep-all работает
    assert len(ass.assessed) >= 1


def test_mock_mode_no_enrich():
    """enrich=False (mock/dev): внешние БД не вызываются, источник manual."""
    ass = asyncio.run(_assess([dict(VULN_RAW)], nvd=None, bdu=None, enrich=False))
    a = ass.assessed[0]
    assert a["source"] == "manual"
    assert a["cmdb_match"] is True
    assert a["target_version"] == "2.17.0"          # fixed_version выведен регексом из описания
    assert "2.17.0" in a["recommendation"]