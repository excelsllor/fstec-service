"""Клиент NVD API v2 (ТЗ 2.4): CVSS (v3.1 → v3.0 → v2), CPE + уязвимые диапазоны, references.
Ретраи ≤3 (resilience), кэш Redis→memory (cache), суммарный таймаут ≤15 с (KPI ТЗ 1.4)."""
import logging

import httpx

from security_service.http_pool import get_client

from security_service.cache import EMPTY, Cache, MemoryCache
from security_service.enriched import EnrichedVuln
from security_service.resilience import retry_async
from security_service.versioning import build_range
from shared.config import NVD_API_BASE, NVD_API_KEY, SECURITY_CACHE_TTL_S

logger = logging.getLogger("fstec.security.nvd")

_SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
    "NONE": "low",
}


def _pick_metrics(cve: dict) -> dict | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30"):
        data = (metrics.get(key) or [])
        if data:
            return data[0]
    data = metrics.get("cvssMetricV2") or []
    return data[0] if data else None


def _base_severity(cvss: dict | None) -> str:
    if not cvss:
        return "unknown"
    raw = cvss.get("baseSeverity") or (cvss.get("cvssData") or {}).get("baseSeverity") or ""
    return _SEVERITY_MAP.get(str(raw).upper(), "unknown")


def _configurations(cve: dict) -> list:
    out = []
    for conf in cve.get("configurations") or []:
        for node in conf.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                if not m.get("vulnerable"):
                    continue
                out.append(build_range(m.get("criteria", ""), m))
    return out


def _references(cve: dict) -> list[dict]:
    return [
        {"source": r.get("source", ""), "url": r.get("url", "")}
        for r in (cve.get("references") or []) if r.get("url")
    ]


def _description(cve: dict) -> str:
    for d in cve.get("descriptions") or []:
        if d.get("lang") in ("en", ""):
            return d.get("value", "")
    return ""


class NVDClient:
    def __init__(self, cache: Cache | None = None, base_url: str = NVD_API_BASE,
                 api_key: str = NVD_API_KEY, transport=None):
        self.cache = cache or MemoryCache()
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.transport = transport

    async def _fetch(self, cve_id: str) -> dict | None:
        headers = {"X-Api-Key": self.api_key} if self.api_key else {}
        url = f"{self.base_url}/rest/json/cves/2.0"
        if self.transport is not None:
            kwargs = {"timeout": httpx.Timeout(10.0, connect=5.0), "transport": self.transport}
            async with httpx.AsyncClient(**kwargs) as client:
                resp = await client.get(url, params={"cveId": cve_id}, headers=headers)
        else:
            client = get_client("nvd", timeout=10.0, connect=5.0)
            resp = await client.get(url, params={"cveId": cve_id}, headers=headers)
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
        vulns = data.get("vulnerabilities") or []
        return vulns[0].get("cve") if vulns else None

    async def get_cve(self, cve_id: str) -> EnrichedVuln | None:
        cve_id = (cve_id or "").strip()
        if not cve_id:
            return None
        key = f"nvd:{cve_id}"
        cached = await self.cache.get(key)
        if cached is not None:
            if cached is EMPTY or not cached:
                return None
            return EnrichedVuln(**{k: cached[k] for k in cached if k in EnrichedVuln.__dataclass_fields__})

        cve = await retry_async(self._fetch, cve_id)
        if cve is None:
            await self.cache.set(key, None)
            return None

        metrics = _pick_metrics(cve)
        cvss_data = (metrics or {}).get("cvssData") or {}
        description = _description(cve)
        obj = EnrichedVuln(
            source="nvd",
            cve_id=cve_id,
            title=cve.get("id", cve_id),
            description=description,
            severity=_base_severity(metrics or cvss_data),
            cvss_score=cvss_data.get("baseScore"),
            cvss_vector=(cvss_data.get("vectorString", "") or ""),
            cvss_version=(cvss_data.get("version", "") or ""),
            cpe_matches=_configurations(cve),
            patch_url="",
            references=_references(cve),
        )
        await self.cache.set(key, obj.normalize())
        return obj