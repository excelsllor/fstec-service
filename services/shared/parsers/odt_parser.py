import io
import xml.etree.ElementTree as ET
import zipfile

from shared.parsers._xml_guard import guard_zip_xml
from shared.parsers.base import ParseResult

NS = {
    "office": "urn:oasis:names:tc:opendocument:xmlns:office:1.0",
    "text": "urn:oasis:names:tc:opendocument:xmlns:text:1.0",
    "table": "urn:oasis:names:tc:opendocument:xmlns:table:1.0",
}


def parse_odt(content: bytes) -> ParseResult:
    result = ParseResult()
    if not guard_zip_xml(content, what="ODT", errors=result.errors):
        return result
    try:
        zf = zipfile.ZipFile(io.BytesIO(content))
        xml_bytes = zf.read("content.xml")
        zf.close()
        root = ET.fromstring(xml_bytes)
        text_parts = []
        tables = []
        body = root.find(".//office:body", NS)
        if body is None:
            result.errors.append("ODT: нет body")
            return result
        content_el = body.find("office:text", NS)
        if content_el is None:
            result.errors.append("ODT: нет office:text")
            return result
        for child in content_el:
            tag = child.tag.split("}")[-1]
            if tag == "p":
                line = _get_text(child)
                if line.strip():
                    text_parts.append(line)
            elif tag == "table":
                table = _parse_table(child)
                if table:
                    tables.append(table)
                    for row in table:
                        for cell in row:
                            if cell.strip():
                                text_parts.append(cell)
        result.text = "\n".join(text_parts)
        result.tables = tables
    except Exception as e:
        result.errors.append(f"ODT: {e}")
    return result


def _get_text(el) -> str:
    parts = []
    for node in el.iter():
        if node.text:
            parts.append(node.text)
        if node.tail:
            parts.append(node.tail)
    return "".join(parts)


def _parse_table(table_el) -> list[list[str]]:
    rows = []
    for row in table_el.findall("table:table-row", NS):
        cells = []
        for cell in row.findall("table:table-cell", NS):
            cells.append(_get_text(cell).strip())
        if any(c for c in cells):
            rows.append(cells)
    return rows