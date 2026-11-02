"""Версионный matching (ТЗ 2.4): нормализация версий, проверка попадания в уязвимый
диапазон, сопоставление по CPE и именам продуктов."""
import re

from security_service.enriched import CpeMatch, RangeSpec

_SEP_RE = re.compile(r"[._\-+ ]+")


def normalize_version(v: str) -> tuple[int, ...] | None:
    """'1.1.1k' / '2.15.0' / '108.0.1462.42' → числовой кортеж (буквенный суффикс отбрасывается)."""
    if not v:
        return None
    parts: list[int] = []
    for token in _SEP_RE.split(v.strip()):
        m = re.match(r"(\d+)", token)
        if m:
            parts.append(int(m.group(1)))
        elif parts:
            break
    return tuple(parts) if parts else None


def compare_versions(a: str, b: str) -> int:
    """-1/0/1; сравниваем числовые компоненты и буквенный суффикс (1.1.1k vs 1.1.1w)."""
    pa, pb = _version_parts(a), _version_parts(b)
    if not pa or not pb:
        return 0
    for (na, sa), (nb, sb) in zip(pa, pb):
        if na != nb:
            return -1 if na < nb else 1
        if sa != sb:
            if not sa:
                return -1
            if not sb:
                return 1
            return -1 if sa < sb else 1
    if len(pa) != len(pb):
        return -1 if len(pa) < len(pb) else 1
    return 0


def _version_parts(v: str) -> list[tuple[int, str]]:
    """Числовые компоненты + буквенный суффикс: 1.1.1k -> (1,''),(1,''),(1,'k')."""
    parts: list[tuple[int, str]] = []
    for token in _SEP_RE.split((v or "").strip()):
        m = re.match(r"(\d+)([A-Za-z][A-Za-z0-9]*)?", token)
        if m:
            parts.append((int(m.group(1)), (m.group(2) or "").lower()))
        elif parts:
            break
    return parts


def in_range(version: str, spec: RangeSpec) -> bool:
    """Версия входит в уязвимый диапазон (>= min [<= max]) по NVD/BDU."""
    t = normalize_version(version)
    if t is None:
        return False
    if spec.min_version:
        cmp_min = compare_versions(version, spec.min_version)
        if cmp_min < 0 or (cmp_min == 0 and not spec.min_inclusive):
            return False
    if spec.max_version:
        cmp_max = compare_versions(version, spec.max_version)
        if cmp_max > 0 or (cmp_max == 0 and not spec.max_inclusive):
            return False
    return True


def _cpe_parts(cpe: str) -> tuple[str, str] | None:
    """'cpe:2.3:a:openssl:openssl:1.1.1k:*...' → (vendor, product) с '*' как 'meant any'."""
    m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):", cpe)
    if not m:
        return None
    vendor, product = m.group(1), m.group(2)
    if vendor == "*":
        vendor = ""
    if product == "*":
        product = ""
    return vendor.lower(), product.lower()


def _cpe_has_version(cpe: str) -> bool:
    m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+)", cpe)
    return bool(m and m.group(3) and m.group(3) != "*")


def match_cpe(vuln_cpes: list[str], item_cpe: str) -> bool:
    """Строгий CPE-матч: одинаковая часть/vendor/product; '*' в vuln CPE = любой."""
    item = _cpe_parts(item_cpe)
    if not item:
        return False
    for cpe in vuln_cpes:
        v = _cpe_parts(cpe)
        if not v:
            continue
        if v == item:
            return True
        # запись уязвимости с '*' по vendor/product покрывает любой инвентарь
        if (not v[0] or not item[0] or v[0] == item[0]) and (not v[1] or not item[1] or v[1] == item[1]):
            ranges_match = _cpe_matches_product(v[0], v[1], item[0], item[1])
            if ranges_match:
                return True
    return False


def _cpe_matches_product(v_vendor: str, v_product: str, i_vendor: str, i_product: str) -> bool:
    vv, vp = v_vendor or "", v_product or ""
    iv, ip = i_vendor or "", i_product or ""
    return (vv == iv or not vv or not iv) and (vp == ip or not vp or not ip)


def product_names(name: str) -> set[str]:
    """Нормализованные варианты имени продукта для fuzzy-матча."""
    n = (name or "").lower().strip()
    out = {n}
    for sep in (",", " ", "\t"):
        if sep in n:
            out.add(n.split(sep)[0])
    # 'Apache Log4j' → 'log4j'; 'openssl' → 'openssl'
    return {n for n in out if n}


def match_product(inventory_name: str, vuln_software: str | list[str]) -> bool:
    """Подстрочный fuzzy-матч имени продукта (normalized): 'openssl' ∈ 'openssl project'."""
    names = [inventory_name] if isinstance(inventory_name, str) else inventory_name
    targets = [vuln_software] if isinstance(vuln_software, str) else vuln_software
    for n in names:
        for t in targets:
            nn = (n or "").lower().strip()
            tt = (t or "").lower().strip()
            if not nn or not tt:
                continue
            if nn in tt or tt in nn:
                return True
    return False


def build_range(criteria: str, raw_range: dict | None) -> CpeMatch:
    """Из cpeMatch-узла NVD (versionStart*/versionEnd*) собирает CpeMatch с диапазонами."""
    rr = raw_range or {}
    spec = RangeSpec(
        min_version=rr.get("versionStartIncluding", "") or rr.get("versionStartExcluding", ""),
        min_inclusive=bool(rr.get("versionStartIncluding")),
        max_version=rr.get("versionEndIncluding", "") or rr.get("versionEndExcluding", ""),
        max_inclusive=bool(rr.get("versionEndIncluding")),
    )
    if not spec.is_specified and _cpe_has_version(criteria):
        m = re.match(r"cpe:2\.3:[aoh]:([^:]+):([^:]+):([^:]+)", criteria)
        if m and m.group(3) != "*":
            spec = RangeSpec(min_version=m.group(3), max_version=m.group(3), raw=m.group(3))
    return CpeMatch(criteria=criteria, ranges=[spec])


def vuln_range_hit(version: str, cpe_matches: list[CpeMatch]) -> bool:
    """Версия входит хотя бы в один заданный диапазон CPE-записи (без учёта имени CPE)."""
    for m in cpe_matches:
        for r in m.ranges:
            if r.is_specified and in_range(version, r):
                return True
    return False