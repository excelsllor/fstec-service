"""NER-хевристики (ТЗ 2.3.2 «стандартные: организации, сроки, контакты»).

В проде дополняются LLM-валидацией через llm-service (Qwen3-14B). Здесь —
быстрый регулярный базис, гарантирующий KPI до подключения модели.
"""
import re
from dataclasses import dataclass, field

from shared.extractor.patterns import PHONE_PATTERN

KNOWN_ORGS = [
    "ФСТЭК России",
    "Правительство Липецкой области",
    "Федеральная служба по техническому и экспортному контролю",
    "Минцифры России",
    "Минкомсвязь России",
    "Национальный координационный центр по компьютерным инцидентам",
    "НКЦКИ",
]


# Сроки: «в течение N дней/недель/месяцев» | «не позднее N …» | «в срок до N …»
# даты «до DD.MM.YYYY» и «до DD месяц ГГГГ г.»
_PERIOD = r"(?:календарн[а-яё]+\s+)?(день|дня|дней|недел[а-яё]+|месяц[а-яё]+|месяцев)"
_DEADLINE_PERIOD = re.compile(
    r"(?:в\s+течение|не\s+позднее|в\s+срок\s+(?:до\s+)?)\s*(\d{1,3})\s+" + _PERIOD,
    re.IGNORECASE,
)
_DEADLINE_DATE = re.compile(r"до\s+(\d{1,2})[./](\d{1,2})[./](\d{4})", re.IGNORECASE)
_DEADLINE_DATE_TEXT = re.compile(
    r"до\s+(\d{1,2})\s+([а-яё']+)\s+(\d{4})\s*г(?:ода)?\.?", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"\b[\w.+-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.(?:[A-Za-z]{2,10})\b")

_MONTHS = {
    "января": 1, "февраля": 2, "марта": 3, "апреля": 4, "мая": 5, "июня": 6,
    "июля": 7, "августа": 8, "сентября": 9, "октября": 10, "ноября": 11, "декабря": 12,
}


@dataclass
class NERResult:
    organizations: list[str] = field(default_factory=list)
    deadlines: list[str] = field(default_factory=list)
    contacts: list[str] = field(default_factory=list)


_ORG_FORMS = re.compile(
    r'(?:ООО|АО|ПАО|ЗАО|ОАО|АНО|ИП|ФГУП|МУП|ГКУ|ОГКУ|КУ)?\s*[«"]([^«»"]{3,90})[»"]',
    re.IGNORECASE,
)

_ORG_JUNK = ("троян", "стилер", "загрузчик", "бэкдор", "дроппер", "шифровальщик",
             "кейлоггер", "майнер", "ботнет", "червь", "sandbox", "песочниц",
             "карантин", "антивирус", "реестр", "учетных", "панель",
             "компонент", "фильтрац", "список", "правил", "защита", "обновлен",
             "tor hidden", "hidden service", "hwmonitor", "perfmonitor", "cpu-z",
             "anydesk", "rustdesk", "netsupport", "powershell", "clickfix",
             "rclone", "gsocket", "openssh", "win+r", "форум", "forkadmin")
_ORG_STOP = {"и", "по", "для", "на", "о", "об", "в", "к", "с", "от", "из",
             "при", "до", "за", "а", "но", "или", "г", "гг"}


def _looks_like_org(name: str) -> bool:
    s = name.strip().replace("\xa0", " ")
    if "\n" in s or re.search(r"[.\\/:;,=_+*#№\d]", s):
        return False
    if _ORG_FORMS_LEGAL.search(s):
        return True
    low = s.lower()
    if any(t in low for t in _ORG_JUNK):
        return False
    words = [w for w in s.split()]
    if len(words) < 2:
        return False
    meaningful = 0
    for w in words:
        head = w.split("-")[0].strip("«»\"")
        if head.lower() in _ORG_STOP:
            continue
        ch = head[0] if head else ""
        if not (ch.isupper() and ch.isalpha()):
            return False
        meaningful += 1
    return meaningful >= 2


_ORG_FORMS_LEGAL = re.compile(
    r'^(?:ООО|АО|ПАО|ЗАО|ОАО|АНО|ИП|ФГУП|МУП|ГКУ|ОГКУ|КУ|ГУП)\b', re.IGNORECASE)


def extract_standard_ner(text: str) -> NERResult:
    result = NERResult()
    text = text.replace("\xa0", " ")
    seen_orgs, seen_deadlines, seen_contacts = set(), set(), set()

    for org in KNOWN_ORGS:
        if org.lower() in text.lower() and org not in seen_orgs:
            result.organizations.append(org)
            seen_orgs.add(org)

    for m in _ORG_FORMS.finditer(text):
        name = m.group(1).strip()
        if 3 <= len(name) <= 90 and _looks_like_org(name) and name not in seen_orgs:
            result.organizations.append(name)
            seen_orgs.add(name)

    for m in _DEADLINE_PERIOD.finditer(text):
        value = f"{m.group(1)} {m.group(2)}"
        if value not in seen_deadlines:
            result.deadlines.append(value)
            seen_deadlines.add(value)

    for m in _DEADLINE_DATE.finditer(text):
        value = f"до {m.group(1)}.{m.group(2)}.{m.group(3)}"
        if value not in seen_deadlines:
            result.deadlines.append(value)
            seen_deadlines.add(value)

    for m in _DEADLINE_DATE_TEXT.finditer(text):
        mon = _MONTHS.get(m.group(2).lower())
        if mon is None:
            continue
        value = f"до {m.group(1)}.{mon:02d}.{m.group(3)}"
        if value not in seen_deadlines:
            result.deadlines.append(value)
            seen_deadlines.add(value)

    for m in PHONE_PATTERN.finditer(text):
        phone = re.sub(r"\s+", "", m.group(0))
        if phone not in seen_contacts:
            result.contacts.append(phone)
            seen_contacts.add(phone)

    for m in _EMAIL_RE.finditer(text):
        email = m.group(0)
        if email not in seen_contacts:
            result.contacts.append(email)
            seen_contacts.add(email)

    return result