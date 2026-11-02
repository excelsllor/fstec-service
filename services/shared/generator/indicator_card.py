import io
from datetime import date
from pathlib import Path

from shared.config import ORG_NAME

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, Cm, RGBColor

# Цветовая индикация рисков (ТЗ 4.4)
RISK_COLORS = {
    "critical": "C0392B",   # красный
    "high": "E67E22",
    "medium": "F1C40F",     # жёлтый
    "low": "D4EFDF",
    "no_risk": "27AE60",    # зелёный
}


def _set_cell_bg(cell, hex_color: str):
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)
    tc_pr.append(shd)


def _create_doc():
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Times New Roman"
    style.font.size = Pt(12)
    for section in doc.sections:
        section.page_width = Cm(21.0)
        section.page_height = Cm(29.7)
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(3)
        section.right_margin = Cm(1.5)
    return doc


def _heading(doc, text: str, size: int = 16, center: bool = True):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER if center else WD_ALIGN_PARAGRAPH.LEFT
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(size)


def _section_title(doc, text: str):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(13)


def _line(doc, text: str, indent: bool = False):
    p = doc.add_paragraph()
    if indent:
        p.paragraph_format.left_indent = Cm(0.75)
    p.add_run(text)


# Двухчастные общедоступные суффиксы (co.uk, com.au, ...): корневой домен = 3 последние метки
_TWO_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "ac.nz",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "ne.kr", "or.kr", "re.kr", "pe.kr", "go.kr",
    "com.mx", "net.mx", "org.mx", "gob.mx", "edu.mx",
    "com.tr", "net.tr", "org.tr", "gov.tr", "edu.tr",
    "com.ua", "net.ua", "org.ua", "gov.ua", "edu.ua", "in.ua",
    "com.in", "co.in", "net.in", "org.in", "ac.in",
    "com.sg", "net.sg", "org.sg", "edu.sg",
    "com.my", "net.my", "org.my", "edu.my", "gov.my",
    "com.pl", "net.pl", "org.pl",
    "com.pt", "net.pt", "org.pt", "edu.pt",
    "com.ru", "net.ru", "org.ru", "msk.ru", "spb.ru", "nov.ru", "ru.net",
    "com.de", "de.com", "eu.com", "uk.com", "us.com",
    "com.se", "com.es", "com.it", "com.fr", "com.nl", "com.be",
    "com.ec", "com.pe", "com.co", "com.ar", "com.ve",
    "com.eg", "com.ng", "com.za", "co.za", "net.za", "org.za",
    "com.pk", "com.bd",
}


def root_domain(domain: str) -> str:
    """Корневой домен (общедоступный суффикс) — лёгкая эвристика (ТЗ 2.5.1 Раздел 2)."""
    labels = domain.strip(".").lower().split(".")
    if len(labels) <= 2:
        return domain
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def build_indicator_card(
    *,
    org_name: str,
    source_filename: str,
    document_id: int,
    ips: list[str],
    ipv6: list[str],
    domains: list[str],
    emails: list[str],
    vulnerabilities: list[dict],
    sla: str = "normal",
) -> bytes:
    """Карточка индикаторов (ТЗ 2.5.1): шапка + 4 раздела, К/Ж/З-подсветка."""
    doc = _create_doc()
    _heading(doc, org_name or ORG_NAME)

    today = date.today().isoformat()
    _line(doc, f"Дата: {today}")
    _line(doc, f"Исходный файл: {source_filename}")
    _line(doc, f"ID заявки: {document_id}")
    doc.add_paragraph("")

    _section_title(doc, "Раздел 1. Список IP-адресов")
    seen4 = set()
    ipv4 = []
    for entry in ips:
        ip = entry.split(":")[0] if ":" in entry and not _is_ipv6_like(entry) else entry
        if ip not in seen4:
            seen4.add(ip)
            ipv4.append(ip)
    _line(doc, "IPv4:")
    for ip in ipv4:
        _line(doc, f"  • {ip}", indent=True)
    _line(doc, "IPv6:")
    for ip in dict.fromkeys(ipv6):
        _line(doc, f"  • {ip}", indent=True)
    if not ipv4 and not ipv6:
        _line(doc, "  — не обнаружено")

    _section_title(doc, "Раздел 2. Список доменных имен")
    for d in dict.fromkeys(domains):
        _line(doc, f"  • {d}   (корневой домен: {root_domain(d)})", indent=True)
    if not domains:
        _line(doc, "  — не обнаружено")

    _section_title(doc, "Раздел 3. Список Email-адресов")
    for e in dict.fromkeys(emails):
        _line(doc, f"  • {e}", indent=True)
    if not emails:
        _line(doc, "  — не обнаружено")

    _section_title(doc, "Раздел 4. Результаты анализа уязвимостей")
    headers = ["CVE / BDU ID", "CVSS Score", "Затронутое ПО", "Текущая версия", "Целевая версия", "Статус угрозы"]
    table = doc.add_table(rows=1, cols=len(headers))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, h in enumerate(headers):
        cell = table.rows[0].cells[i]
        cell.text = h
        for p in cell.paragraphs:
            for r in p.runs:
                r.bold = True

    if vulnerabilities:
        for v in vulnerabilities:
            status = "Красный (Critical)" if (v.get("cmdb_match") or v.get("severity") == "critical") else (
                "Жёлтый (Medium)" if v.get("severity") in ("high", "medium") else "Зелёный (Low)"
            )
            row = table.add_row().cells
            vals = [
                v.get("cve_id") or v.get("bdu_id") or "",
                str(v.get("cvss_score")) if v.get("cvss_score") is not None else "",
                v.get("software") or "",
                v.get("current_version") or "",
                v.get("target_version") or v.get("fixed_version") or "",
                status,
            ]
            for i, val in enumerate(vals):
                row[i].text = val
            color = "C0392B" if (v.get("cmdb_match") or v.get("severity") == "critical") else (
                "E5E7EB" if v.get("severity") == "unknown" else
                "F1C40F" if v.get("severity") in ("high", "medium") else "27AE60"
            )
            _set_cell_bg(row[-1], color)
    else:
        _line(doc, "Уязвимости не обнаружены")
        p = doc.add_paragraph()
        _set_cell_bg_from_paragraph(p, RISK_COLORS["no_risk"])

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _is_ipv6_like(entry: str) -> bool:
    return entry.count(":") > 1


def _set_cell_bg_from_paragraph(p, color: str):
    pPr = p._p.get_or_add_pPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color)
    pPr.append(shd)


def report_filename(source_filename: str, report_date: date | None = None) -> str:
    report_date = report_date or date.today()
    safe = Path(source_filename).stem
    return f"Report_{safe}_{report_date.isoformat()}.docx"