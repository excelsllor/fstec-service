"""BDU-клиент: парсинг живой print-страницы (v_model), legacy-фолбек, graceful."""
import asyncio

import httpx

from security_service.bdu_client import BDUClient, _cvss_from_critu, _severity_from_critu
from security_service.cache import MemoryCache
from tests.fakes import BDU_HTML, BDU_LEGACY_HTML, bdu_transport


def _bdu() -> BDUClient:
    return BDUClient(cache=MemoryCache(), transport=bdu_transport())


def test_parse_bdu_print_html():
    obj = BDUClient.parse_page(BDU_HTML, "BDU:2024-12345")
    assert obj is not None
    assert obj.source == "bdu"
    assert obj.bdu_id == "BDU:2024-12345"
    assert obj.severity == "critical"
    assert obj.cvss_score == 9.8
    assert obj.cvss_version == "3.1"
    assert obj.fixed_version == "2.17.0"
    assert obj.cve_id == "CVE-2021-44228"
    assert "Log4j2" in obj.title
    assert obj.patch_url == "https://logging.apache.org/log4j/2.x/security.html"


def test_prefers_cvss_31_over_20_even_with_higher_20_score():
    critu = ("Критический уровень опасности (базовая оценка CVSS 2.0 составляет 10.0)\r\n"
             "Высокий уровень опасности (базовая оценка CVSS 3.1 составляет 8.8)")
    assert _cvss_from_critu(critu) == (8.8, "3.1")
    assert _severity_from_critu(critu) == "high"


def test_parse_legacy_html():
    obj = BDUClient.parse_page(BDU_LEGACY_HTML, "BDU:2024-12345")
    assert obj is not None
    assert obj.severity == "critical"
    assert obj.cvss_score == 9.8
    assert obj.fixed_version == "2.17.0"
    assert any(c.startswith("cpe:2.3:a:apache:log4j") for c in obj.cpes)
    assert obj.patch_url


def test_parse_garbage_returns_none():
    assert BDUClient.parse_page("<html><body>no vuln data</body></html>", "BDU:9999-99999") is None


def test_get_bdu_roundtrip():
    obj = asyncio.run(_bdu().get_bdu("BDU:2024-12345"))
    assert obj is not None and obj.fixed_version == "2.17.0"


def test_get_bdu_unknown_returns_none():
    assert asyncio.run(_bdu().get_bdu("BDU:9999-99999")) is None


def test_network_failure_graceful():
    transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("no net")))
    client = BDUClient(cache=MemoryCache(), transport=transport)
    try:
        asyncio.run(client.get_bdu("BDU:2024-12345"))
        assert False, "ожидали ExternalServiceError после исчерпания ретраев"
    except Exception as exc:
        assert "failed after" in str(exc)