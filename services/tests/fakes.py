"""Фейковые внешние БД/инвентарь для тестов Фазы 3 (offline-CI, phase1_json_schemas.md §1-3)."""
import json

import httpx

from security_service.enriched import CpeMatch, EnrichedVuln, RangeSpec

NVD_FIXTURE = {
    "resultsPerPage": 1,
    "vulnerabilities": [{
        "cve": {
            "id": "CVE-2021-44228",
            "descriptions": [{"lang": "en", "value": "A remote code execution vulnerability in Apache Log4j affecting versions 2.0 <= x <= 2.16.0."}],
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                    }
                }]
            },
            "configurations": [{
                "nodes": [{
                    "cpeMatch": [{
                        "vulnerable": True,
                        "criteria": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                        "versionStartExcluding": "2.0",
                        "versionEndIncluding": "2.16.0",
                    }]
                }]
            }],
            "references": [
                {"source": "vendor", "url": "https://logging.apache.org/log4j/2.x/security.html"},
            ],
        }
    }],
}

NVD_CRITICAL = EnrichedVuln(
    source="nvd", cve_id="CVE-2021-44228", title="CVE-2021-44228",
    description="Log4j RCE <=2.16.0", severity="critical", cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", cvss_version="3.1",
    cpe_matches=[CpeMatch(criteria="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                          ranges=[RangeSpec(min_version="2.0", min_inclusive=False,
                                            max_version="2.16.0", max_inclusive=True,
                                            raw="(2.0, 2.16.0]")])],
    patch_url="https://logging.apache.org/log4j/2.x/security.html",
)

BDU_HTML = """
<html><body>
<title>БДУ - Уязвимость BDU:2024-12345</title>
<h1>Банк данных угроз безопасности информации</h1>
<p>Идентификатор уязвимости: CVE-2021-44228</p>
<script type="application/json">const v_model = reactive({
"vul_name": "Уязвимость компонента JNDI библиотеки журналирования Apache Log4j2, позволяющая нарушителю выполнить произвольный код",
"vul_critu": "Критический уровень опасности (базовая оценка CVSS 2.0 составляет 9.3)\\r\\nКритический уровень опасности (базовая оценка CVSS 3.1 составляет 9.8)",
"vul_desc": "Уязвимость компонента JNDI связана с недостаточной проверкой вводимых данных. Эксплуатация может позволить нарушителю выполнить произвольный код.",
"vul_vmer": "Использование рекомендаций: необходимо произвести обновление до версии 2.17.0",
"vul_link": "https://logging.apache.org/log4j/2.x/security.html\\r\\nhttps://access.redhat.com/security/cve/CVE-2021-44228"
});</script>
</body></html>
"""

BDU_LEGACY_HTML = """
<html><body>
<h1>BDU:2024-12345</h1>
<p>Уязвимость в программном обеспечении Apache Log4j. Уровень опасности: Критический.
Базовый вектор CVSS: 9.8. Устраняется в версии 2.17.0.</p>
<table><tr><td>cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*</td></tr></table>
<a href="https://logging.apache.org/log4j/2.x/security.html">рекомендации производителя</a>
</body></html>
"""

BDU_ENRICHED = EnrichedVuln(
    source="bdu", bdu_id="BDU:2024-12345", title="BDU:2024-12345",
    description="Уязвимость в программном обеспечении Apache Log4j",
    severity="critical", cvss_score=9.8,
    cpe_matches=[CpeMatch(criteria="cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")],
    fixed_version="2.17.0",
    patch_url="https://logging.apache.org/log4j/2.x/security.html",
)

VULN_RAW = {
    "bdu_id": "BDU:2024-12345",
    "cve_id": "CVE-2021-44228",
    "description": "Эксплуатация уязвимости Apache Log4j, уровень опасности по CVSS 9.8 — "
                   "критический. Необходимо произвести обновление до версии 2.17.0.",
    "software": "Apache Log4j",
    "severity": "critical",
}


def nvd_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if "CVE-2021-44228" in request.url.params.get("cveId", ""):
            return httpx.Response(200, json=NVD_FIXTURE)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


def bdu_transport() -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if "/vul/print/2024-12345" in request.url.path:
            return httpx.Response(200, text=BDU_HTML)
        return httpx.Response(404)
    return httpx.MockTransport(handler)


class FakeNVDClient:
    """Возвращает фиксированный NVD_CRITICAL; при fail=True бросает исключение (тест ретраев)."""

    def __init__(self, result: EnrichedVuln | None = NVD_CRITICAL, fail: bool = False):
        self.result = result
        self.fail = fail
        self.calls: list[str] = []

    async def get_cve(self, cve_id: str) -> EnrichedVuln | None:
        self.calls.append(cve_id)
        if self.fail:
            raise RuntimeError("NVD unavailable")
        return self.result


class FakeBDUClient:
    def __init__(self, result: EnrichedVuln | None = BDU_ENRICHED, fail: bool = False):
        self.result = result
        self.fail = fail
        self.calls: list[str] = []

    async def get_bdu(self, bdu_id: str) -> EnrichedVuln | None:
        self.calls.append(bdu_id)
        if self.fail:
            raise RuntimeError("BDU unavailable")
        return self.result


def load_nvd_fixture() -> dict:
    return json.loads(json.dumps(NVD_FIXTURE))