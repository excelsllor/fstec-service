import re

HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
HASH_SHA512 = re.compile(r"\b[a-fA-F0-9]{128}\b")
HASH_SHA384 = re.compile(r"\b[a-fA-F0-9]{96}\b")

IP_OBFUSCATED = re.compile(r"(\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})\[\.\](\d{1,3})")
IP_OBFUSCATED_PAREN = re.compile(r"(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})\(\.\)(\d{1,3})")

# IPv4 без CIDR-суффикса (требование ТЗ 2.3.2: CIDR выделяется отдельно).
# Хвостовой \b намеренно не ставится: в реальных списках бывает мусор после
# адреса ("203.0.113.10l", ".162l") — срезаем по (?!\d).
IP_PLAIN = re.compile(r"(?<![0-9.])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?!/\d)(?!\.\d)(?!\d)")
IPV4_CIDR = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")

# IPv6 candidate; validated by ipaddress in ioc_extractor.
IPV6_PLAIN = re.compile(
    r"(?<![0-9A-Za-z:])((?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:/\d{1,3})?)(?![0-9A-Za-z:])",
    re.IGNORECASE,
)
IPV6_EMBEDDED = re.compile(
    r"(?<![0-9A-Za-z:])((?:::ffff:\d{1,3}(?:\.\d{1,3}){3})|(?:[0-9A-Fa-f]{1,4}:){1,4}:\d{1,3}(?:\.\d{1,3}){3})(?![/0-9A-Za-z:])",
    re.IGNORECASE,
)

DOMAIN_OBFUSCATED = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
# ????????? ??????: ????? ????? ???????, ????? ? [.] ??? (.).
DOMAIN_MIXED = re.compile(
    r"(?<![-\w.])((?:[a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\]|\(\.\)|\.))+[a-zA-Z]{2,10})(?![-\w])"
)
DOMAIN_OBFUSCATED_PAREN = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9\-]*(?:\(\.\)[a-zA-Z0-9][a-zA-Z0-9\-]*)+)"
)
DOMAIN_PLAIN = re.compile(r"(?<![-\w.])((?:[a-zA-Z0-9][a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,10})(?![-\w])")

EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

BDU_PATTERN = re.compile(r"(?:BDU|БДУ)[:\s]*\s*(\d{4}-\d{3,6})", re.IGNORECASE)
CVE_PATTERN = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)

_ID_BDU_SPLIT = re.compile(r"(?i)((?:BDU|БДУ)[:\s]*\d{4})\s*[-–]\s*(\d{3,6})")
_ID_CVE_SPLIT = re.compile(r"(?i)\b(CVE)\s*[-–]?\s*(\d{4})\s*[-–]?\s*(\d{4,7})\b")


def normalize_vuln_ids(text: str) -> str:
    """Склеивает идентификаторы, разорванные переносом строки/пробелом:
    «BDU:2026-\\n10606» → «BDU:2026-10606», «CVE-2024-\\n1234» → «CVE-2024-1234»."""
    text = _ID_BDU_SPLIT.sub(r"\1-\2", text)
    text = _ID_CVE_SPLIT.sub(r"\1-\2-\3", text)
    return text

VDB_URL_PATTERN = re.compile(
    r"(?:https?://)?(?:www\.)?"
    r"(?:"
    r"nvd\.nist\.gov/vuln/detail/[A-Za-z0-9-]+"
    r"|cve\.mitre\.org/(?:cgi-bin/cvename\.cgi\?name=)?[A-Za-z0-9-]+"
    r"|bdu\.fstec\.ru/vul(?:/|\?)?[0-9][0-9A-Za-z_-]*"
    r"|nvd\.nist\.gov|cve\.mitre\.org|bdu\.fstec\.ru"
    r")",
    re.IGNORECASE,
)
VDB_HOSTS = {"nvd.nist.gov", "cve.mitre.org", "bdu.fstec.ru", "www.nvd.nist.gov", "www.cve.mitre.org", "www.bdu.fstec.ru"}

PORT_PATTERN = re.compile(r":(\d{1,5})\b")

# NER: контакты (ТЗ 2.3.2)
PHONE_PATTERN = re.compile(
    r"(?:\+7\s?[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"
    r"|8\s?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})"
)
DEADLINE_PATTERN = re.compile(
    r"(?:в\s+течение|не\s+позднее|в\s+срок|до\s+)\s*"
    r"(?:(\d{1,3})\s+(?:календарн[а-яё]+\s+)?(?:день|дня|дней|недел[а-яё]+|месяц[а-яё]+|месяцев|дней))"
    r"|до\s+(\d{1,2})[./](\d{1,2})[./](\d{4})",
    re.IGNORECASE,
)

KNOWN_GROUPS = [
    "Rare Werewolf", "Cloud Werewolf", "Fluffy Wolf", "Fairy Wolf",
    "Watch Wolf", "Rainbow Hyena", "Vortex Werewolf", "Sticky Werewolf",
    "Versatile Werewolf", "Hoody Hyena", "Forbidden Hyena", "Geo Likho",
    "Paper Werewolf", "Shedding Zmiy", "Iridescent Hyena",
    "UAT-8302", "UAT-5776",
    "Vengeful Wolf", "Clubfoot Wolf", "Core Werewolf",
    "Cavalry Werewolf", "Larcenous Werewolf", "Fairy Werewolf",
    "King Werewolf", "Silent Werewolf", "Insolent Hyena",
]

MALWARE_NAMES = [
    "Cobalt Strike", "Agent Tesla", "FormBook", "NanoCore",
    "AsyncRAT", "RedLine", "Raccoon", "Vidar", "Lumma",
    "Hta", "hta",
]

ARCHIVE_NAMES = re.compile(
    r'(?:архив\s+(?:с\s+)?(?:наименованием|названием)\s*[«"]([^«»"]+)[»"])',
    re.IGNORECASE,
)

EXE_NAMES = re.compile(
    r'(?:исполняем[а-яё]+\s+файл\s+(?:с\s+)?(?:наименованием|названием)\s*[«"]([^«»"]+)[»"])',
    re.IGNORECASE,
)

THEME_PATTERN = re.compile(
    r'(?:на\s+тему|тематик\w*|тем\w*)\s*[«"]([^«»"]+)[»"]',
    re.IGNORECASE,
)

SEVERITY_PATTERN = re.compile(
    r"(критическ[а-яё]+|высок[а-яё]+|средн[а-яё]+|низк[а-яё]+)",
    re.IGNORECASE,
)
