import re
from dataclasses import dataclass
from shared.extractor.patterns import BDU_PATTERN, CVE_PATTERN, KNOWN_GROUPS, normalize_vuln_ids

# Соотносится со следующей фразой про исправление: «обновление до версии 2.17.0»
_BDU_URL = re.compile(r"https?://(?:www\.)?bdu\.fstec\.ru/vul/(\d{4}-\d{3,6})", re.IGNORECASE)

_PATCH_SENTENCE = re.compile(
    r"(?:обновлени[а-яё]*|устраня(?:ется|ются)|переход[а-яё]*|отключ(?:ение|ить))\s+"
    r"(?:до|на)\s+(?:версии|версию)|\bверси[а-яё]*\s+[\d.]+",
    re.IGNORECASE,
)

# Канонические наименования продуктов: (regex-поиск по предложению, канон).
# Применяются РАНЬШЕ generic-эвристики, чтобы «печати» не затирали Samba и т.п.
_KNOWN_PRODUCTS: list[tuple[str, str]] = [
    (r"catalyst\s+sd-wan\s+manager", "Cisco Catalyst SD-WAN Manager"),
    (r"oracle\s+(?:weblogic\s+server|fusion\s+middleware)", "Oracle Weblogic Server / Fusion Middleware"),
    (r"apache\s+flink\s+kubernetes\s+operator", "Apache Flink Kubernetes Operator"),
    (r"microsoft\s+sharepoint\s+server", "Microsoft SharePoint Server"),
    (r"sharepoint\s+enterprise\s+server", "Microsoft SharePoint Enterprise Server"),
    (r"\bsamba\b", "Samba"),
    (r"\bglpi\b", "GLPI"),
    (r"\bsudo\b", "Sudo"),
    (r"\binfluxdb\b", "InfluxDB"),
    (r"check\s+point\s+spark", "Check Point Spark"),
    (r"check\s+point\s+remote\s+access\s+vpn", "Check Point Remote Access VPN"),
    (r"next\.?js", "Next.js"),
    (r"\breact\b", "React"),
    (r"\bclickfix\b", "ClickFix"),
    (r"1c(?:-)?бит|1с\s*:?предприятие", "1С:Предприятие"),
]


@dataclass
class VulnInfo:
    bdu_id: str = ""
    cve_id: str = ""
    description: str = ""
    software: str = ""
    version: str = ""
    severity: str = "unknown"


def extract_vulns(text: str, tables: list | None = None) -> list[VulnInfo]:
    results = []
    seen = set()
    text = normalize_vuln_ids(text.replace("\xa0", " "))

    for m in BDU_PATTERN.finditer(text):
        bdu = f"BDU:{m.group(1)}"
        if bdu in seen:
            continue
        seen.add(bdu)
        sentence_end = _find_sentence_end_with_patch(text, m.end())
        sentence = text[_find_sentence_start(text, m.start()): sentence_end]
        results.append(VulnInfo(
            bdu_id=bdu,
            description=sentence.strip()[:500],
            software=_extract_software(sentence, m.group(0)),
            version=_extract_version(sentence),
            severity=_extract_severity(sentence, m.group(0)),
        ))

    for m in CVE_PATTERN.finditer(text):
        cve = m.group(1).upper()
        key = f"CVE:{cve}"
        if key in seen:
            continue
        seen.add(key)
        sentence_end = _find_sentence_end_with_patch(text, m.end())
        sentence = text[_find_sentence_start(text, m.start()): sentence_end]
        results.append(VulnInfo(
            cve_id=cve,
            description=sentence.strip()[:500],
            software=_extract_software(sentence, m.group(0)),
            version=_extract_version(sentence),
            severity=_extract_severity(sentence, m.group(0)),
        ))

    for m in _BDU_URL.finditer(text):
        bdu = f"BDU:{m.group(1)}"
        if bdu in seen:
            continue
        seen.add(bdu)
        sentence_end = _find_sentence_end_with_patch(text, m.end())
        sentence = text[_find_sentence_start(text, m.start()): sentence_end]
        results.append(VulnInfo(
            bdu_id=bdu,
            description=sentence.strip()[:500],
            software=_extract_software(sentence, m.group(0)),
            version=_extract_version(sentence),
            severity=_extract_severity(sentence, m.group(0)),
        ))

    if tables:
        for table in tables:
            for row in table:
                row_text = " ".join((c or "") for c in row)
                for m in BDU_PATTERN.finditer(row_text):
                    bdu = f"BDU:{m.group(1)}"
                    if bdu not in seen:
                        seen.add(bdu)
                        results.append(VulnInfo(bdu_id=bdu, description=row_text[:500]))
    return results


def _find_sentence_start(text: str, pos: int) -> int:
    for i in range(pos, max(0, pos - 500), -1):
        if text[i] in "!?":
            return min(i + 1, pos)
        if text[i] == ".":
            if i > 0 and i + 1 < len(text) and text[i - 1].isdigit() and text[i + 1].isdigit():
                continue
            return min(i + 1, pos)
    return max(0, pos - 500)


def _find_sentence_end(text: str, pos: int) -> int:
    for i in range(pos, min(len(text), pos + 500)):
        if text[i] in "!?":
            return i + 1
        if text[i] == ".":
            if i > 0 and i + 1 < len(text) and text[i - 1].isdigit() and text[i + 1].isdigit():
                continue
            return i + 1
    return min(len(text), pos + 500)


def _find_sentence_end_with_patch(text: str, pos: int, lookahead: int = 260) -> int:
    """Расширяет окно на следующее предложение, если в нём указан патч
    («обновление до версии 2.17.0»), чтобы derive-fixed_version получил версию."""
    end = _find_sentence_end(text, pos)
    if end >= len(text) - 1:
        return end
    seg = text[end:end + lookahead]
    if _PATCH_SENTENCE.search(seg):
        return _find_sentence_end(text, end)
    return end


def extract_software_items(text: str) -> list[dict]:
    """????????? ????????? ???????? ? ????????? ?????? ??? ??????????? ?? CVE/BDU."""
    items: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for pat, canon in _KNOWN_PRODUCTS:
        for m in re.finditer(pat, text or "", re.IGNORECASE):
            tail = (text or "")[m.end():m.end() + 120]
            vm = re.search(r"(?<![0-9A-Za-z])([0-9]+(?:\.[0-9]+){1,4}[A-Za-z]?)(?![0-9A-Za-z])", tail)
            version = vm.group(1) if vm else ""
            key = (canon, version)
            if key not in seen:
                seen.add(key)
                items.append({"name": canon, "version": version})
    return items


def _canonical_product(sentence: str) -> str:
    """Ищет известные продукты в предложении; возвращает каноническое имя."""
    norm_sent = sentence.lower()
    for pat, canon in _KNOWN_PRODUCTS:
        if re.search(pat, norm_sent, re.IGNORECASE):
            return canon
    return ""


def _extract_software(sentence: str, bdu_str: str = "") -> str:
    bad_words = {"cvss", "gsocket", "backdoor", "бэкдор", "троян", "стилер",
                 "червь", "файл", "архив", "письмо", "уровень", "опасности",
                 "danger", "vulnerability", "эксплуатация", "уязвимост",
                 "группировк", "осуществляет", "атак", "проводится"}
    bad_words |= {g.lower() for g in KNOWN_GROUPS}
    canon = _canonical_product(sentence)
    if canon:
        return canon
    first_bdu = None
    if bdu_str and bdu_str in sentence:
        first_bdu = re.search(r"(?:BDU|БДУ)[:\s]", sentence, re.IGNORECASE)
    if first_bdu:
        for zone in (sentence[:first_bdu.start()], sentence[first_bdu.end():], sentence):
            sw = _find_software_in(zone, bad_words)
            if sw:
                return sw
        return ""
    return _find_software_in(sentence, bad_words)


def _find_software_in(text: str, bad_words: set) -> str:
    m = re.search(
        r"(?:программн[а-яё]+\s+обеспечени[а-яё]+|программного\s+обеспечения|программы|пакета?\s+программ|"
        r"библиотеки|текстового\s+редактора|редактора|"
        r"операционн[а-яё]+\s+систем|системы|средства)\s+"
        r"([A-ZА-Я][\w\s.\-]{2,80}?)\s*(?:\(|,|;|$)",
        text, re.IGNORECASE,
    )
    if m:
        sw = m.group(1).strip().rstrip(",.;:")
        if _is_valid_software(sw, bad_words):
            return sw
    m = re.search(r"([A-Z][A-Za-z][A-Za-z0-9\s.\-]{2,60}?)\s*\(\s*(?:BDU|БДУ)", text)
    if m:
        sw = m.group(1).strip().rstrip(",.;:")
        if _is_valid_software(sw, bad_words):
            return sw
    candidates = re.findall(r"([A-Z][A-Za-z][A-Za-z0-9\s.\-]{2,60})", text)
    for c in reversed(candidates):
        c = c.strip().rstrip(",.;:")
        if _is_valid_software(c, bad_words):
            return c
    return ""


def _is_valid_software(sw: str, bad_words: set) -> bool:
    sw_lower = sw.lower()
    if len(sw) < 3:
        return False
    if sw_lower.endswith((".zip", ".rar", ".exe", ".lnk", ".hta", ".doc",
                          ".docx", ".pdf", ".xls", ".xlsx", ".rtf", ".wsf",
                          ".bat", ".cmd", ".scr")):
        return False
    for w in bad_words:
        if w in sw_lower:
            return False
    if re.search(r"\d{4}", sw):
        return False
    if "_" in sw:
        return False
    if re.match(r"^[А-Яа-яёЁ\s]+$", sw) and len(sw) > 40:
        return False
    return True


# Версии ПО: «версии 2.17.0», «до версии 2.16.0», «Apache Log4j 2.17.x»
_VERSION_PREF = re.compile(
    r"верси[а-яё]+\s+([0-9]+(?:\.[0-9]+){0,3}[A-Za-z0-9_.\-+]*)", re.IGNORECASE)
_VERSION_BARE = re.compile(r"([0-9]+(?:\.[0-9]+){1,3}[A-Za-z0-9_.\-+]*)")
_CVSS_BEFORE = re.compile(r"cvss\s*$", re.IGNORECASE)


def _extract_version(sentence: str) -> str:
    m = _VERSION_PREF.search(sentence)
    if m:
        return m.group(1).strip(".,;:()[]")[:24]
    for m in _VERSION_BARE.finditer(sentence):
        if _CVSS_BEFORE.search(sentence[:m.start()][-12:]):
            continue
        version = m.group(1).strip(".,;:()[]")
        if re.search(r"\d", version):
            return version[:24]
    return ""


def _extract_severity(sentence: str, bdu_str: str) -> str:
    pos = sentence.find(bdu_str)
    if pos < 0:
        return "unknown"
    after = sentence[pos:]
    m = re.search(
        r"уровень\s+опасности\s+по\s+CVSS\s*[\d.]+\s*[-—]\s*"
        r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
        after, re.IGNORECASE,
    ) or re.search(
        r"уровень\s+опасности.{0,30}?"
        r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
        after, re.IGNORECASE,
    ) or re.search(
        r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
        after, re.IGNORECASE,
    )
    if m:
        s = m.group(1).lower()
        if "крит" in s:
            return "critical"
        if "высок" in s:
            return "high"
        if "средн" in s:
            return "medium"
        if "низк" in s:
            return "low"
    return "unknown"