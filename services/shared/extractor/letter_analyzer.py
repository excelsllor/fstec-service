import re
from dataclasses import dataclass, field
from shared.extractor.patterns import (
    KNOWN_GROUPS, MALWARE_NAMES,
    ARCHIVE_NAMES, EXE_NAMES, THEME_PATTERN,
)

MONTHS = {
    "января": "01", "февраля": "02", "марта": "03", "апреля": "04",
    "мая": "05", "июня": "06", "июля": "07", "августа": "08",
    "сентября": "09", "октября": "10", "ноября": "11", "декабря": "12",
}


@dataclass
class ThreatInfo:
    number: int = 0
    group_name: str = ""
    threat_type: str = ""
    theme: str = ""
    archive_name: str = ""
    exe_name: str = ""
    malware_type: str = ""
    description: str = ""
    measures: list[str] = field(default_factory=list)


@dataclass
class LetterInfo:
    letter_number: str = ""
    letter_date: str = ""
    letter_type: str = "hacker"
    threats: list[ThreatInfo] = field(default_factory=list)
    raw_text: str = ""


def analyze_letter(text: str, tables: list | None = None) -> LetterInfo:
    text = text.replace("\xa0", " ")
    info = LetterInfo(raw_text=text)
    info.letter_number = _extract_letter_number(text)
    info.letter_date = _extract_letter_date(text)
    info.letter_type = _detect_type(text)
    if info.letter_type in ("hacker", "compromise"):
        info.threats = _parse_threats(text)
    return info


def _extract_letter_number(text: str) -> str:
    header = text[:2000]
    cleaned = header.replace("_", "")
    m = re.search(r"№\s*(\d+[-/]\d+)", cleaned)
    if m:
        return m.group(1)
    for num in re.findall(r"№\s*(\d+)", cleaned):
        if num != "250":
            return num
    return ""


def _extract_letter_date(text: str) -> str:
    header = text[:2000]
    cleaned = re.sub(r"\s+", " ", re.sub(r"_", "", header))
    patterns = [
        r"(\d{1,2})\s+(" + "|".join(MONTHS.keys()) + r")\s+(\d{4})",
        r"(\d{1,2})\.(\d{1,2})\.(\d{4})",
        r"(\d{4})-(\d{1,2})-(\d{1,2})",
    ]
    for pat in patterns:
        for m in re.finditer(pat, cleaned):
            if pat.startswith(r"(\d{1,2})\s+("):
                day, month, year = m.group(1).zfill(2), MONTHS.get(m.group(2), "01"), m.group(3)
            elif pat.startswith(r"(\d{1,2})\."):
                day, month, year = m.group(1).zfill(2), m.group(2).zfill(2), m.group(3)
            else:
                year, month, day = m.group(1), m.group(2).zfill(2), m.group(3).zfill(2)
            if 2020 <= int(year) <= 2035:
                return f"{year}-{month}-{day}"
    return ""


def _detect_type(text: str) -> str:
    first = text[:5000]
    has_compromise = bool(re.search(
        r"компрометаци[а-яё]+\s+(?:веб-сайта|программн|ПО|сервера|инфраструктуры)",
        first, re.IGNORECASE))
    has_hacker = bool(re.search(
        r"хакерск[а-яё]+\s+группировк|фишингов[а-яё]*\s+рассылк",
        first, re.IGNORECASE))
    has_vuln = bool(re.search(
        r"(?:BDU|БДУ)[:\s]|CVE-\d{4}-|уязвимост[а-яё]+",
        first, re.IGNORECASE))
    if has_hacker:
        return "hacker"
    if has_compromise:
        return "compromise"
    if has_vuln:
        return "vulnerability"
    return "other"


def _parse_threats(text: str) -> list[ThreatInfo]:
    normalized = re.sub(r"\r\n|\r", "\n", text)
    lines = normalized.split("\n")
    threat_keywords = re.compile(
        r"(?:[Хх]акерск[а-яё]+|В\s+случае\s+реализации|"
        r"Для\s+предотвращения|хакерской\s+группировк|"
        r"По\s+имеющейся|сведений\s+об\s+уязвимост|"
        r"компрометац[а-яё]+|Обнаружен[а-яё]+|"
        r"Зафиксирован[а-яё]+|Выявлен[а-яё]+|"
        r"В\s+целях\s+предотвращения|вредоносн[а-яё]+)",
        re.IGNORECASE,
    )
    threat_starts = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        m = re.match(r"^(\d{1,2})\.\s+([^\d])", stripped)
        if m and threat_keywords.match(stripped[m.start(2):]):
            start_pos = sum(len(lines[j]) + 1 for j in range(i))
            threat_starts.append((int(m.group(1)), start_pos, i))
    if not threat_starts:
        return []
    result = []
    full_len = len(normalized)
    for idx, (num, start_pos, _) in enumerate(threat_starts):
        end_pos = threat_starts[idx + 1][1] if idx + 1 < len(threat_starts) else full_len
        section = normalized[start_pos:end_pos]
        threat = ThreatInfo(number=num, description=section.strip())
        threat.threat_type = _detect_threat_type(section)
        for group in KNOWN_GROUPS:
            if group.lower() in section.replace("\xa0", " ").lower():
                threat.group_name = group
                break
        theme_m = THEME_PATTERN.search(section)
        if theme_m:
            threat.theme = theme_m.group(1)
        archive_m = ARCHIVE_NAMES.search(section)
        if archive_m:
            threat.archive_name = archive_m.group(1)
        exe_m = EXE_NAMES.search(section)
        if exe_m:
            threat.exe_name = exe_m.group(1)
        for mw in MALWARE_NAMES:
            if mw.lower() in section.lower():
                threat.malware_type = mw
                break
        threat.measures = _extract_measures(section)
        result.append(threat)
    return result


def _extract_measures(section: str) -> list[str]:
    section = re.sub(r"(?m)^\s*\d{1,3}\s*$", "", section or "")
    numbered = list(re.finditer(r"(?<!\d)(\d+\.\d+)\.\s+", section))
    if len(numbered) >= 2:
        out: list[str] = []
        for idx, match in enumerate(numbered):
            end = numbered[idx + 1].start() if idx + 1 < len(numbered) else len(section)
            chunk = section[match.start():end]
            chunk = re.sub(r"^\d+\.\d+\.\s*", "", chunk)
            chunk = re.sub(r"\s+", " ", chunk).strip(" .;")
            if len(chunk) >= 10 and chunk not in out:
                out.append(chunk)
        if out:
            return out[:50]

    text = re.sub(r"\s*\n\s*", " ", section or "")
    text = re.sub(r"\s+", " ", text).strip()
    marker = re.compile(
        r"(?:\u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c\u043e"
        r"|\u043f\u0440\u0438\u043d\u044f\u0442\u044c"
        r"|\u0440\u0435\u0430\u043b\u0438\u0437\u043e\u0432\u0430\u043d[\u0430\u044b]?"
        r"|\u0441\u043b\u0435\u0434\u0443\u0435\u0442"
        r"|\u043e\u0431\u0435\u0441\u043f\u0435\u0447\u0438\u0442\u044c"
        r"|\u043f\u0440\u043e\u0438\u0437\u0432\u043e\u0434\u0438(?:\u0442\u0441\u044f|\u0442\u044c)"
        r"|\u043f\u0440\u043e\u0438\u0437\u0432\u0435\u0434\u0435\u043d[\u0430-\u044f\u0451]+)",
        re.IGNORECASE,
    )
    bad = re.compile(r"(?:\u043f\u0440\u0438\s+\u0440\u0435\u0430\u043b\u0438\u0437\u0430\u0446\u0438\u0438.*\u0432\u0440\u0435\u0434\u043e\u043d\u043e\u0441\u043d)", re.IGNORECASE)
    sentences = re.split(r"(?<=[.!?;])\s+", text)
    out = []
    for sentence in sentences:
        s = sentence.strip()
        if not s or bad.search(s):
            continue
        m = marker.search(s)
        if not m:
            continue
        clause = s[m.start():].strip(" .;")
        if len(clause) >= 10 and clause not in out:
            out.append(clause)
    return out[:50]

def _detect_threat_type(section: str) -> str:
    s = section.lower()
    if re.search(r"(?:bd|бд)у[:\s]|cve-\d{4}", s):
        return "vulnerability"
    if "компрометаци" in s and ("веб-сайта" in s or "разработчика" in s):
        return "compromise"
    if "clickfix" in s:
        return "clickfix"
    if "фишинг" in s or "phishing" in s or "фишингов" in s:
        return "phishing"
    if re.search(r"вредоносн[а-яё]+\s+программн", s):
        return "malware_attack"
    if re.search(r"троян|стилер|бэкдор|backdoor|червь|rat\b", s):
        return "malware_attack"
    return "malware_attack"
