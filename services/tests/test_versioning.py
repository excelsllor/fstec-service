"""Версионный matching (ТЗ 2.4): semver-нормализация, диапазоны, CPE/product-матчи."""
import asyncio

from security_service.enriched import CpeMatch, RangeSpec
from security_service.versioning import (build_range, compare_versions, in_range,
                                         match_cpe, match_product, normalize_version,
                                         vuln_range_hit)


def test_normalize_version():
    assert normalize_version("1.1.1k") == (1, 1, 1)
    assert normalize_version("2.15.0") == (2, 15, 0)
    assert normalize_version("108.0.1462.42") == (108, 0, 1462, 42)
    assert normalize_version("") is None
    assert normalize_version("openssl") is None


def test_compare_versions():
    assert compare_versions("2.15.0", "2.16.0") == -1
    assert compare_versions("2.17.0", "2.16.0") == 1
    assert compare_versions("1.1.1k", "1.1.1") == 1
    assert compare_versions("1.1.1k", "1.1.1w") == -1
    assert compare_versions("1.1.1k", "1.1.1k") == 0
    assert compare_versions("2.15", "2.15.0") == -1


def test_in_range():
    spec = RangeSpec(min_version="2.0", min_inclusive=False, max_version="2.16.0", max_inclusive=True)
    assert in_range("2.15.0", spec)
    assert in_range("2.16.0", spec)      # max включительно
    assert not in_range("2.0", spec)     # min исключительно
    assert not in_range("2.17.0", spec)
    assert not in_range("abc", spec)
    assert in_range("2.15.0", RangeSpec())  # пустой диапазон не ограничивает


def test_build_range_from_nvd():
    m = build_range("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    {"versionStartExcluding": "2.0", "versionEndIncluding": "2.16.0"})
    assert m.ranges[0].is_specified
    assert m.ranges[0].min_inclusive is False
    assert m.ranges[0].max_inclusive is True
    assert vuln_range_hit("2.15.0", [m])
    assert not vuln_range_hit("2.17.0", [m])


def test_match_cpe():
    assert match_cpe(["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                     "cpe:2.3:a:apache:log4j:2.15.0:*:*:*:*:*:*:*")
    assert not match_cpe(["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"],
                         "cpe:2.3:a:microsoft:edge:108.0:*:*:*:*:*:*:*")


def test_match_product():
    assert match_product("Log4j", "Apache Log4j")
    assert match_product("OpenSSL Project", "openssl")
    assert match_product("Microsoft Edge", "OpenSSL") is False


async def _async_hit():
    return True


def test_vuln_range_hit_multi():
    m1 = CpeMatch(criteria="cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                  ranges=[RangeSpec(max_version="1.1.1k", max_inclusive=True)])
    assert vuln_range_hit("1.1.1k", [m1])
    assert not vuln_range_hit("3.0.0", [m1])