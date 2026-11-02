"""NVD API v2 клиент: разбор CVSS/CPE/диапазонов, кэш, 404→None, graceful сбой."""
import asyncio

import httpx

from security_service.cache import MemoryCache
from security_service.nvd_client import NVDClient
from tests.fakes import nvd_transport


def _nvd() -> NVDClient:
    return NVDClient(cache=MemoryCache(), transport=nvd_transport())


def test_get_cve_parses():
    obj = asyncio.run(_nvd().get_cve("CVE-2021-44228"))
    assert obj is not None
    assert obj.source == "nvd"
    assert obj.cve_id == "CVE-2021-44228"
    assert obj.severity == "critical"
    assert obj.cvss_score == 9.8
    assert obj.cvss_vector.startswith("CVSS:3.1")
    assert obj.cpe_matches and obj.cpe_matches[0].criteria == "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert obj.affected_range
    assert obj.references


def test_get_cve_unknown_returns_none():
    assert asyncio.run(_nvd().get_cve("CVE-9999-0000")) is None


def test_get_cve_empty():
    assert asyncio.run(_nvd().get_cve("")) is None


def test_cache_hit_avoids_http():
    cache = MemoryCache()
    client = NVDClient(cache=cache, transport=nvd_transport())
    asyncio.run(client.get_cve("CVE-2021-44228"))
    # подменяем транспорт на «обрушенный» — второй вызов должен взяться из кэша
    client.transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("no net")))
    obj = asyncio.run(client.get_cve("CVE-2021-44228"))
    assert obj is not None and obj.cve_id == "CVE-2021-44228"