"""Security Posture Analyzer (ТЗ 2.4): обогащение NVD/BDU → сопоставление с CMDB →
версионный matching → recommendation/SLA. Keep-all: ВСЕ уязвимости письма возвращаются
(cmatch_match — флаг), рекомендация по формуле «Обновить {P} с {a} до {b}»."""
import asyncio
import logging
import re
from dataclasses import dataclass, field

from security_service.cmdb import InventoryClient, InventoryItem
from security_service.enriched import EnrichedVuln
from security_service.versioning import (compare_versions, match_cpe, match_product,
                                         normalize_version, vuln_range_hit)
from shared.config import SECURITY_MODE

logger = logging.getLogger("fstec.security.assessment")

UPDATE_TEMPLATE = "Обновить ПО до указанной версии, закрывающей уязвимость"

_FIXED_RE = re.compile(
    r"(?:до\s+версии|устраня(?:ется|емой|емых)\s+.*?версии?|fixed\s+in|patched\s+in)"
    r"[:]?\s*([A-Za-z0-9][\w.\-]*)",
    re.IGNORECASE,
)


def derive_fixed_version(enriched: EnrichedVuln | None, raw_description: str = "") -> str:
    """fixed_version: структурированное поле BDU/NVD, иначе regex по описанию («до версии X»)."""
    if enriched and enriched.fixed_version:
        return enriched.fixed_version
    text = raw_description or (enriched.description if enriched else "")
    m = _FIXED_RE.search(text)
    if m:
        candidate = m.group(1).rstrip(".,;:")
        if re.match(r"^[\w.]", candidate):
            return candidate
    return ""


async def _enrich(vuln: dict, nvd, bdu) -> tuple[EnrichedVuln | None, str]:
    """Обогащает raw-уязвимость клиентами внешних БД.

    Для BDU-записей источником истины является BDU: именно BDU задаёт
    версию CVSS (3.1) и severity для ответа ФСТЭК. NVD используется как
    дополнительный источник CPE/диапазонов версий, если BDU их не дал.
    """
    cve_id = (vuln.get("cve_id") or "").strip()
    bdu_id = (vuln.get("bdu_id") or "").strip()
    errors: list[str] = []
    found: dict[str, EnrichedVuln] = {}
    requests = []
    if nvd and cve_id:
        requests.append(("NVD", cve_id, nvd.get_cve(cve_id)))
    if bdu and bdu_id:
        requests.append(("BDU", bdu_id, bdu.get_bdu(bdu_id)))
    if requests:
        results = await asyncio.gather(*(task for _, _, task in requests), return_exceptions=True)
        for (kind, vid, _), result in zip(requests, results):
            if isinstance(result, Exception):
                logger.warning("%s lookups failed for %s: %s", kind, vid, result)
                errors.append(f"{kind}:{vid}:{result}")
            elif isinstance(result, EnrichedVuln):
                found[kind] = result

    bdu_result = found.get("BDU")
    nvd_result = found.get("NVD")
    if bdu_result is not None:
        if nvd_result is not None:
            if not bdu_result.cpe_matches:
                bdu_result.cpe_matches = nvd_result.cpe_matches
            if not bdu_result.fixed_version:
                bdu_result.fixed_version = nvd_result.fixed_version
            if not bdu_result.patch_url:
                bdu_result.patch_url = nvd_result.patch_url
            if not bdu_result.cve_id:
                bdu_result.cve_id = nvd_result.cve_id
            if not bdu_result.cvss_version:
                bdu_result.cvss_version = nvd_result.cvss_version
        return bdu_result, "; ".join(errors)
    if nvd_result is not None:
        return nvd_result, "; ".join(errors)
    return None, "; ".join(errors)


def _cpe_ok(matcher, item_cpe: str) -> bool:
    """True если CPE-запись уязвимости похожа на CPE инвентаря (по vendor/product)."""
    from security_service.versioning import _cpe_parts
    v = _cpe_parts(matcher.criteria)
    i = _cpe_parts(item_cpe)
    if not v or not i:
        return False
    return (not v[0] or not i[0] or v[0] == i[0]) and (not v[1] or not i[1] or v[1] == i[1])


def _match_cmdb(enriched: EnrichedVuln | None, candidates: list[InventoryItem],
                software: str, fixed_hint: str = "") -> tuple[InventoryItem | None, bool]:
    """Выбирает лучшего кандидата CMDB и определяет версионный match (ТЗ 2.4).

    Match = (CPE-совпадение ∥ product-совпадение) ∧ (нет диапазона ∨ версия в диапазоне).
    """
    if not candidates:
        return None, False
    range_info = bool(enriched and any(
        r.is_specified for m in enriched.cpe_matches for r in m.ranges))
    for item in candidates:
        if not item.installed:
            continue
        cpe_hit = bool(enriched and enriched.cpes and item.cpe
                       and match_cpe(enriched.cpes, item.cpe))
        name_hit = match_product(item.name, software)
        if not (cpe_hit or name_hit):
            continue
        version_hit = False
        fixed_for_check = (enriched.fixed_version if enriched else fixed_hint)
        if item.version:
            if range_info and enriched:
                if cpe_hit and item.cpe:
                    targets = [m for m in enriched.cpe_matches if _cpe_ok(m, item.cpe)]
                    if not targets:
                        targets = enriched.cpe_matches
                else:
                    targets = enriched.cpe_matches
                version_hit = bool(targets) and vuln_range_hit(item.version, targets)
            elif fixed_for_check:
                version_hit = compare_versions(item.version, fixed_for_check) < 0
            elif enriched is None:
                version_hit = True
        if not version_hit:
            continue
        return item, True
    return None, False


def _severity(enriched: EnrichedVuln | None, raw: dict) -> str:
    if enriched and enriched.severity != "unknown":
        return enriched.severity
    return raw.get("severity") or "unknown"


@dataclass
class Assessment:
    assessed: list[dict] = field(default_factory=list)
    external_errors: list[str] = field(default_factory=list)
    sla: str = "normal"
    routing: str = "default"


async def _assess_one(v: dict, *, cmdb, enrich: bool, nvd, bdu, cmdb_cache: dict | None = None) -> tuple[dict, str]:
    """Обогащение + сопоставление с CMDB для одной уязвимости."""
    raw = dict(v or {})
    software = " ".join((raw.get("software") or "").split())
    enriched: EnrichedVuln | None = None
    if enrich and (raw.get("cve_id") or raw.get("bdu_id")) and nvd and bdu:
        enriched, errs = await _enrich(raw, nvd, bdu)
        err_text = errs
    else:
        err_text = ""

    fixed = derive_fixed_version(enriched, raw.get("description", ""))
    item, matched = None, False
    cmdb_error = ""
    candidates: list[InventoryItem] = []
    try:
        if cmdb_cache is not None and software in cmdb_cache:
            candidates = cmdb_cache[software]
        else:
            candidates = await cmdb.find_many(software)
            if cmdb_cache is not None:
                cmdb_cache[software] = candidates
        item, matched = _match_cmdb(enriched, candidates, software, fixed_hint=fixed)
    except Exception as exc:  # noqa: BLE001 — CMDB недоступна (ТЗ 4.2)
        logger.warning("cmdb lookup failed for %r: %s", software, exc)
        cmdb_error = f"cmdb:{software}:{exc}"
        err_text = "; ".join(x for x in (err_text, f"cmdb:{software}:{exc}") if x)

    installed = [candidate for candidate in candidates if candidate.installed]
    current_version = (item.version if item else
                       (installed[0].version if installed else ""))
    if cmdb_error:
        applicable = None
    else:
        applicable = bool(installed)
    if matched:
        action_type = "update" if fixed else "compensate"
    elif applicable is not None:
        action_type = "skip"
    else:
        action_type = ""
    notes = ""
    if installed and current_version:
        notes = (f"ПО «{installed[0].name}» {current_version} найдено в GLPI (список ПО); "
                 f"{installed[0].assets} запись в списке.")
    elif applicable is False:
        notes = f"ПО «{software}» не найдено в установленном ПО GLPI."
    rec = (f"Обновить {item.name if item else software} с {current_version} до {fixed}"
           if matched and fixed else UPDATE_TEMPLATE)
    return {
        "cve_id": enriched.cve_id if enriched and enriched.cve_id else raw.get("cve_id", ""),
        "bdu_id": enriched.bdu_id if enriched and enriched.bdu_id else raw.get("bdu_id", ""),
        "description": enriched.description if enriched and enriched.description else raw.get("description", ""),
        "software": software,
        "severity": _severity(enriched, raw),
        "cvss_score": enriched.cvss_score if enriched else raw.get("cvss_score"),
        "cvss_version": enriched.cvss_version if enriched else raw.get("cvss_version", ""),
        "cpe": enriched.cpes[0] if enriched and enriched.cpes else (raw.get("cpe") or ""),
        "affected_range": enriched.affected_range if enriched else (raw.get("affected_range") or ""),
        "fixed_version": fixed,
        "patch_url": enriched.patch_url if enriched else (raw.get("patch_url") or ""),
        "cmdb_match": matched,
        "cmdb_error": cmdb_error,
        "current_version": current_version,
        "target_version": fixed,
        "recommendation": rec,
        "source": enriched.source if enriched else "manual",
        "is_applicable": applicable,
        "action_type": action_type,
        "applicability_notes": notes,
    }, err_text


async def assess_document(vulns_raw: list[dict], *, cmdb: InventoryClient,
                          enrich: bool | None = None, nvd=None, bdu=None,
                          letter_type: str = "") -> Assessment:
    """Полный цикл ТЗ 2.4. enrich=False → без внешних вызовов (mock/dev-режим).

    Этап 4: уязвимости одного письма обрабатываются параллельно (ранее строго
    последовательно), но не более SECURITY_LOOKUP_CONCURRENCY одновременно —
    это ограничивает давление на NVD/BDU/CMDB. Порядок результата совпадает с
    порядком во входном списке."""
    from shared.concurrency import bounded_gather
    from shared.config import SECURITY_LOOKUP_CONCURRENCY

    enrich = SECURITY_MODE == "live" if enrich is None else enrich
    vulns = list(vulns_raw or [])
    if not vulns:
        return Assessment(assessed=[], external_errors=[], sla="normal", routing="default")

    cmdb_cache: dict = {}

    # Один запрос GLPI на уникальное ПО на документ, а не на каждую уязвимость.
    unique_products = sorted({
        " ".join((v.get("software") or "").split())
        for v in vulns if " ".join((v.get("software") or "").split())
    })

    async def _warm_cmdb(product: str) -> None:
        try:
            cmdb_cache[product] = await cmdb.find_many(product)
        except Exception:  # noqa: BLE001 — ошибку обработает _assess_one
            pass

    if cmdb is not None and unique_products:
        await bounded_gather(
            [_warm_cmdb(product) for product in unique_products],
            SECURITY_LOOKUP_CONCURRENCY,
            name="cmdb-prefetch",
        )

    results = await bounded_gather(
        [_assess_one(v, cmdb=cmdb, enrich=enrich, nvd=nvd, bdu=bdu, cmdb_cache=cmdb_cache)
         for v in vulns],
        SECURITY_LOOKUP_CONCURRENCY,
        name="security",
    )
    out: list[dict] = []
    external_errors: list[str] = []
    for rec, err_text in results:
        out.append(rec)
        if err_text:
            external_errors.append(err_text)

    cmdb_failed = any(a.get("cmdb_error") for a in out)
    sla_score = "critical" if (
        any(a.get("cmdb_match") for a in out)
        or (letter_type or "").lower() in ("compromise", "clickfix")
    ) else "normal"
    routing = "infosec" if sla_score == "critical" or (letter_type or "").lower() in ("compromise", "clickfix") else "default"
    return Assessment(assessed=out, external_errors=external_errors, sla=sla_score, routing=routing)
