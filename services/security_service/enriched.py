"""Нормализованная модель уязвимости (после обогащения NVD/BDU) — phase1_json_schemas.md §4."""
from dataclasses import dataclass, field


def _clean(s: str | None) -> str:
    return (s or "").strip()


@dataclass
class RangeSpec:
    """Диапазон уязвимых версий. Поля необязательны; None = граница не задана.

    min_inclusive/max_inclusive: включать ли граничную версию (cpeMatch NVD).
    """
    min_version: str = ""
    min_inclusive: bool = True
    max_version: str = ""
    max_inclusive: bool = True
    raw: str = ""

    @property
    def is_specified(self) -> bool:
        return bool(self.min_version or self.max_version)

    def __str__(self) -> str:
        if self.raw:
            return self.raw
        parts = []
        if self.min_version:
            parts.append((">=" if self.min_inclusive else ">") + self.min_version)
        if self.max_version:
            parts.append(("<=" if self.max_inclusive else "<") + self.max_version)
        return ",".join(parts) if parts else "*"


@dataclass
class CpeMatch:
    criteria: str = ""
    ranges: list[RangeSpec] = field(default_factory=list)


@dataclass
class EnrichedVuln:
    """Единая нормализованная уязвимость из внешних БД (nvd|bdu|manual)."""
    source: str = "manual"            # nvd | bdu | manual
    cve_id: str = ""
    bdu_id: str = ""
    title: str = ""
    description: str = ""
    severity: str = "unknown"         # critical|high|medium|low|unknown
    cvss_score: float | None = None
    cvss_vector: str = ""
    cvss_version: str = ""
    cpe_matches: list[CpeMatch] = field(default_factory=list)
    fixed_version: str = ""
    patch_url: str = ""
    references: list[dict] = field(default_factory=list)

    @property
    def cpes(self) -> list[str]:
        return [m.criteria for m in self.cpe_matches if m.criteria]

    @property
    def affected_range(self) -> str:
        specs = [r for m in self.cpe_matches for r in m.ranges if r.is_specified]
        return "; ".join(str(r) for r in specs) if specs else "*"

    def normalize(self) -> dict:
        return {
            "source": self.source,
            "cve_id": self.cve_id,
            "bdu_id": self.bdu_id,
            "title": _clean(self.title),
            "description": _clean(self.description),
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cvss_version": self.cvss_version,
            "cpe": ";".join(self.cpes),
            "affected_range": self.affected_range,
            "fixed_version": _clean(self.fixed_version),
            "patch_url": _clean(self.patch_url),
            "references": self.references,
        }