"""Генераторы тестовых файлов всех поддерживаемых форматов (без внешних writer-библиотек)."""

import io
import struct
import zipfile

from docx import Document as DocxDocument
from openpyxl import Workbook

PIP_TEXT = (
    "Информируем об атаках группировки Rare Werewolf и эксплуатации уязвимости CVE-2021-44228 "
    "(BDU:2024-12345) в Apache Log4j до версии 2.17.0, CVSS 9.8, целевой адрес evil.com 203.0.113.10. "
    "Необходимо произвести обновление до версии 2.17.0 до 01.06.2025."
)

IOC_MARKERS = ["CVE-2021-44228", "BDU:2024-12345", "Rare Werewolf", "Log4j"]


def make_docx_bytes(text: str = PIP_TEXT) -> bytes:
    buf = io.BytesIO()
    d = DocxDocument()
    for line in text.split("\n"):
        d.add_paragraph(line)
    d.save(buf)
    return buf.getvalue()


def make_xlsx_bytes(text: str = PIP_TEXT) -> bytes:
    buf = io.BytesIO()
    wb = Workbook()
    ws = wb.active
    ws.title = "Информация"
    for i, line in enumerate(text.split("\n"), start=1):
        ws.cell(row=i, column=1, value=line)
    wb.save(buf)
    return buf.getvalue()


def make_rtf_bytes(text: str = PIP_TEXT) -> bytes:
    body = []
    for line in text.split("\n"):
        body.append(f"\\pard\\sa200\\sl276\\slmult1 {line}\\par")
    rtf = "{\\rtf1\\ansi\\ansicpg1251\\deff0 {\\fonttbl {\\f0 Consolas;}}\\f0\\fs20 " + "".join(body) + "}"
    return rtf.encode("utf-8")


def make_txt_bytes(text: str = PIP_TEXT) -> bytes:
    return text.encode("utf-8")


def make_odt_bytes(text: str = PIP_TEXT) -> bytes:
    buf = io.BytesIO()
    paragraphs = "".join(f"<text:p>{line}</text:p>" for line in text.split("\n"))
    content_xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<office:document-content office:version="1.2" '
        ' xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
        ' xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" '
        ' xmlns:table="urn:oasis:names:tc:opendocument:xmlns:table:1.0">'
        "<office:body><office:text>" + paragraphs + "</office:text></office:body>"
        "</office:document-content>"
    )
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.text", compress_type=zipfile.ZIP_STORED)
        zf.writestr("content.xml", content_xml)
    return buf.getvalue()


def make_pdf_bytes(text: str = PIP_TEXT) -> bytes:
    """Минимальный одностраничный PDF (ASCII-текст, Helvetica)."""
    text = "".join(c if ord(c) < 128 else "?" for c in text)
    lines = []
    for line in text.split("\n"):
        lines.append(f"BT /F1 10 Tf 72 {720 - 14 * len(lines)} Td ({line}) Tj ET")
        if len(lines) > 40:
            break
    content_stream = "\n".join(lines)
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        "/Resources << /Font << /F1 5 0 R >> >> >> endobj",
        f"4 0 obj << /Length {len(content_stream.encode('latin-1'))} >> stream\n{content_stream}\nendstream endobj",
        "5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]
    pdf = b"%PDF-1.4\n"
    offsets = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj.encode("latin-1") + b"\n"
    xref_pos = len(pdf)
    count = len(objects) + 1
    pdf += f"xref\n0 {count}\n".encode("latin-1")
    pdf += b"0000000000 65535 f \n"
    for off in offsets:
        pdf += f"{off:010d} 00000 n \n".encode("latin-1")
    pdf += (
        f"trailer << /Size {count} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("latin-1")
    )
    return pdf


def _cfb_uint32(b, off, val):
    struct.pack_into("<I", b, off, val)


def make_doc_bytes(text: str = PIP_TEXT) -> bytes:
    """Минимальный валидный бинарный .doc (OLE2/CFB) с потоком WordDocument (FIB)."""
    payload = bytearray(4096)
    payload[0:2] = struct.pack("<H", 0xA5EC)  # FIB magic WordDocument
    utf16 = text.encode("utf-16-le")
    payload[256:256 + len(utf16)] = utf16
    ascii_ioc = "CVE-2021-44228 evil.com 203.0.113.10 BDU:2024-12345 Apache Log4j".encode("ascii")
    payload[2048:2048 + len(ascii_ioc)] = ascii_ioc

    SECTOR = 512
    n_data_sectors = (len(payload) + SECTOR - 1) // SECTOR
    dir_sector = 1
    data_first = 2
    n_total = data_first + n_data_sectors  # sectors: 0=FAT,1=dir,2.. = data

    header = bytearray(SECTOR)
    header[0:8] = bytes.fromhex("D0CF11E0A1B11AE1")
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 0x0003)  # major version
    struct.pack_into("<H", header, 28, 0xFFFE)  # byte order
    struct.pack_into("<H", header, 30, 9)       # sector shift 512
    struct.pack_into("<H", header, 32, 6)       # mini sector shift
    struct.pack_into("<I", header, 44, 0)       # num dir sectors
    struct.pack_into("<I", header, 48, 1)       # num FAT sectors
    struct.pack_into("<I", header, 52, dir_sector)
    struct.pack_into("<Q", header, 64, 0x1000)  # mini stream cutoff
    struct.pack_into("<I", header, 68, 0xFFFFFFFE)  # first mini FAT = EOC
    struct.pack_into("<I", header, 72, 0)
    struct.pack_into("<I", header, 76, 0xFFFFFFFE)  # first DIFAT = EOC
    struct.pack_into("<I", header, 80, 0)
    struct.pack_into("<I", header, 76, 0)  # DIFAT[0] = FAT sector 0

    fat = bytearray(SECTOR)
    _cfb_uint32(fat, 0 * 4, 0xFFFFFFFD)  # sector0 = FAT itself
    _cfb_uint32(fat, dir_sector * 4, 0xFFFFFFFE)  # dir EOC
    for i in range(n_data_sectors):
        nxt = 0xFFFFFFFE if i == n_data_sectors - 1 else data_first + i + 1
        _cfb_uint32(fat, (data_first + i) * 4, nxt)
    for i in range(n_total, SECTOR // 4):
        _cfb_uint32(fat, i * 4, 0xFFFFFFFF)  # FREESECT

    directory = bytearray(SECTOR)
    entry = 0
    name = "Root Entry\x00".encode("utf-16-le")
    directory[entry * 128: entry * 128 + len(name)] = name
    struct.pack_into("<H", directory, entry * 128 + 64, len(name))
    directory[entry * 128 + 66] = 5  # root storage
    directory[entry * 128 + 67] = 1  # black
    struct.pack_into("<I", directory, entry * 128 + 68, 0xFFFFFFFF)
    struct.pack_into("<I", directory, entry * 128 + 72, 0xFFFFFFFF)
    struct.pack_into("<I", directory, entry * 128 + 76, 1)  # child = stream entry
    struct.pack_into("<I", directory, entry * 128 + 116, 0xFFFFFFFE)  # start sector (EOC)
    struct.pack_into("<Q", directory, entry * 128 + 120, 0)

    entry = 1
    name = "WordDocument\x00".encode("utf-16-le")
    directory[entry * 128: entry * 128 + len(name)] = name
    struct.pack_into("<H", directory, entry * 128 + 64, len(name))
    directory[entry * 128 + 66] = 2  # stream
    directory[entry * 128 + 67] = 1  # black
    struct.pack_into("<I", directory, entry * 128 + 68, 0xFFFFFFFF)
    struct.pack_into("<I", directory, entry * 128 + 72, 0xFFFFFFFF)
    struct.pack_into("<I", directory, entry * 128 + 76, 0xFFFFFFFF)
    struct.pack_into("<I", directory, entry * 128 + 116, data_first)
    struct.pack_into("<Q", directory, entry * 128 + 120, len(payload))

    out = bytearray()
    out += header
    out += fat
    out += directory
    for i in range(n_data_sectors):
        seg = payload[i * SECTOR:(i + 1) * SECTOR]
        out += seg.ljust(SECTOR, b"\x00")
    return bytes(out)


BUILDERS = {
    ".docx": make_docx_bytes,
    ".xlsx": make_xlsx_bytes,
    ".odt": make_odt_bytes,
    ".rtf": make_rtf_bytes,
    ".txt": make_txt_bytes,
    ".pdf": make_pdf_bytes,
    ".doc": make_doc_bytes,
}