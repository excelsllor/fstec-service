"""Генерация проекта ответа (ТЗ 2.5.2).

- угроза/уязвимость есть → требование/рекомендация срочного обновления
  (без раскрытия внутренней архитектуры Заказчика);
- угрозы нет → уведомление, что ПО не подвержено риску.
"""
import io
import re

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm

ANTI_PHISHING = [
    "производится автоматическая проверка вложений с использованием имеющейся «песочницы» («sandbox») для выявления вредоносной активности на этапе приема письма почтовым сервером;",
    "производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;",
    "осуществляется автоматическая проверка указанных в письмах URL-адресов, содержащихся в электронных письмах, с использованием механизмов анализа ссылок;",
    "в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;",
    "сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;",
    "работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

MINIMAL = [
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

COMPROMISE = [
    "регулярно производится контроль журналов DNS-серверов, прокси-серверов, средств межсетевого экранирования и средств обнаружения и реагирования уровня узла;",
    "произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

NO_RISK_TEXT = "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации."

_FW_START = re.compile(r"^[\[(:.\-]*?(?:fwd|fw|re|переслан\w*)[\[\]:).\d]*$", re.IGNORECASE)
_FW_SEP = re.compile(r"^[\s\[(:.\d\]]+$")


def _clean_theme(theme: str) -> str:
    """Убирает почтовые форварды (Fwd:/Re:/Re[2]:, «Пересланное письмо») и хвосты."""
    if not theme or not theme.strip():
        return ""
    tokens = theme.split()
    i = 0
    while i < len(tokens):
        t = tokens[i].strip()
        if not t or _FW_START.match(t):
            i += 1
            while i < len(tokens) and _FW_SEP.match(tokens[i].strip()):
                i += 1
        else:
            break
    return " ".join(tokens[i:]).strip(" :-–—._")


def _inflect(measures: list[str], addr_count: int) -> list[str]:
    if addr_count != 1:
        return list(measures)
    return [m.replace("указанным адресам", "указанному адресу") for m in measures]


def generate_reply_text(
    *,
    letter_number: str,
    letter_date: str,
    letter_type: str,
    threats: list[dict],
    vulnerabilities: list[dict],
    addr_count: int,
) -> str:
    """Текстовый проект ответа по ТЗ 2.5.2. vulnerabilities — оценки security-сервиса."""
    num = letter_number or ""
    dt = letter_date or ""
    if dt and re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        dt = f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    lines = [f"Ответ на письмо {num} от {dt}".strip() if num else "Ответ на письмо"]
    lines.append("")
    lines.append("Сообщаем о принятых мерах по повышению защищенности информационной инфраструктуры.")

    is_vuln_letter = letter_type == "vulnerability"
    active_vulns = [v for v in vulnerabilities if v.get("cmdb_match") or v.get("is_applicable") is True]
    if active_vulns:
        lines.append("")
        lines.append("Выявлены уязвимости, затрагивающие используемое программное обеспечение. "
                     "Требуется срочно выполнить обновление:")
        for v in active_vulns:
            sw = v.get("software") or "программного обеспечения"
            cur = ""
            tgt = v.get("target_version") or v.get("fixed_version")
            rec = ""
            if rec:
                lines.append(f"  - {rec};")
            elif cur and tgt:
                lines.append(f"  - обновить {sw} до {tgt};")
            else:
                lines.append(f"  - обновить {sw};")

    threat_cases = list(
        dict(d)
        for d in (threats or []) if isinstance(d, dict)
    )
    if letter_type == "compromise":
        lines.append("")
        lines.append("В целях предотвращения реализации угроз, связанных со случаем компрометации "
                     "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                     "приняты следующие меры защиты:")
        lines.extend(f"  {m}" for m in COMPROMISE)
    elif threat_cases:
        for i, t in enumerate(threat_cases, 1):
            if i > 1:
                lines.append("")
            lines.extend(_measures_block(i, t, addr_count))
    else:
        lines.append("")
        unknown = [v for v in vulnerabilities if v.get("cmdb_error") and not v.get("cmdb_match")]
        if unknown:
            lines.append("Проверка применимости уязвимостей не завершена: CMDB недоступна. Требуется ручная проверка.")
        else:
            lines.append(NO_RISK_TEXT)

    return "\n".join(lines)


def _measures_block(number: int, t: dict, addr_count: int) -> list[str]:
    lines = []
    desc_low = (t.get("description") or "").lower()
    theme = _clean_theme(t.get("theme") or "")
    group = (t.get("group_name") or "").strip()
    if theme:
        intro = f"связанных с {theme}"
    elif group:
        intro = f"связанных с деятельностью хакерской группировки {group}"
    else:
        intro = "связанных с реализуемыми угрозами безопасности информации"
    lines.append(f"{number}. В целях предотвращения возможности реализации угроз безопасности "
                 f"информации, {intro}, приняты следующие меры защиты:")
    measures = _inflect(MINIMAL, addr_count)
    if t.get("threat_type") == "phishing" or "фишинг" in desc_low:
        measures = _inflect(ANTI_PHISHING, addr_count)
    for m in measures:
        lines.append(f"  {m}")
    return lines


def _create_doc():
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Times New Roman"
    style.font.size = Pt(14)
    style.paragraph_format.line_spacing = 1.0
    style.paragraph_format.space_after = Pt(0)
    for section in doc.sections:
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(3)
        section.right_margin = Cm(1.5)
    return doc


def render_reply_docx(text: str) -> bytes:
    doc = _create_doc()
    first = True
    for raw in text.split("\n"):
        line = raw.rstrip()
        if not line.strip():
            doc.add_paragraph()
            continue
        p = doc.add_paragraph()
        if first:
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER
            run = p.add_run(line.strip())
            run.bold = True
            first = False
        else:
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.paragraph_format.first_line_indent = Cm(1.5)
            p.add_run(line)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()