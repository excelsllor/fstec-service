import io
import struct
import re
import olefile
from shared.parsers.base import ParseResult


def parse_doc(content: bytes) -> ParseResult:
    result = ParseResult()
    try:
        ole = olefile.OleFileIO(io.BytesIO(content))
        if not ole.exists("WordDocument"):
            result.errors.append("DOC: нет потока WordDocument")
            return result
        wd = ole.openstream("WordDocument").read()
        tbl = b""
        for tname in ["1Table", "0Table"]:
            if ole.exists(tname):
                tbl = ole.openstream(tname).read()
                break
        text = _extract_text(wd, tbl)
        result.text = text
        result.tables = []
        if not text.strip() or len(text.strip()) < 100:
            fallback = _fallback_scan(wd)
            if fallback and len(fallback) > len(text):
                result.text = fallback
            if not result.text.strip():
                result.errors.append("DOC: не удалось извлечь текст")
        ole.close()
    except Exception as e:
        result.errors.append(f"DOC: {e}")
    return result


def _extract_text(wd: bytes, tbl: bytes) -> str:
    if len(wd) < 0x01B0:
        return ""
    magic = struct.unpack_from("<H", wd, 0)[0]
    if magic != 0xA5EC:
        return ""
    fc_clx = struct.unpack_from("<I", wd, 0x01A2)[0]
    lcb_clx = struct.unpack_from("<I", wd, 0x01A6)[0]
    clx_text = ""
    if lcb_clx > 0 and fc_clx + lcb_clx <= len(tbl):
        clx_text = _parse_clx(tbl[fc_clx: fc_clx + lcb_clx], wd)
    scan_text = _scan_utf16_russian(wd)
    raw_text = _scan_raw_ioc(wd)
    clx_clean = _clean(clx_text)
    scan_clean = _clean(scan_text)
    raw_clean = _clean(raw_text)
    combined = clx_text
    if len(scan_clean) > len(_clean(combined)):
        combined = scan_text
    if len(raw_clean) > len(_clean(combined)):
        combined = raw_text
    if raw_text and raw_text not in combined:
        combined = combined + "\n" + raw_text
    return combined


def _parse_clx(clx: bytes, wd: bytes) -> str:
    if not clx or clx[0] not in (0x01, 0x02):
        return ""
    pos = 0
    if clx[0] == 0x01:
        cb = struct.unpack_from("<H", clx, 1)[0]
        pos = 3 + cb
        if pos >= len(clx) or clx[pos] != 0x02:
            return ""
        lcb = struct.unpack_from("<I", clx, pos + 1)[0]
        pos += 5
    else:
        lcb = struct.unpack_from("<I", clx, 1)[0]
        pos = 5
    n = (lcb - 4) // 12
    if n <= 0 or n > 500:
        return ""
    cps = []
    off = pos
    for _ in range(n + 1):
        if off + 4 > len(clx):
            return ""
        cps.append(struct.unpack_from("<I", clx, off)[0])
        off += 4
    pcd_base = off
    if cps[0] != 0 or cps[1] > len(wd) * 3 or cps[1] < 1:
        return ""
    parts = []
    prev_cp = 0
    for i in range(n):
        cp_start = cps[i]
        cp_end = cps[i + 1]
        pcd_off = pcd_base + i * 8
        if pcd_off + 8 > len(clx):
            break
        fc_raw = struct.unpack_from("<I", clx, pcd_off)[0]
        fcompress = bool(fc_raw & 0x40000000)
        offset = fc_raw & 0x3FFFFFFF
        cc = cp_end - cp_start
        if cp_start != prev_cp or cc <= 0 or cc > 100000 or offset >= len(wd):
            break
        byte_count = cc if fcompress else cc * 2
        if offset + byte_count > len(wd) + 10:
            break
        try:
            raw = wd[offset: offset + byte_count]
            text = raw.decode("cp1251", errors="replace") if fcompress else raw.decode("utf-16-le", errors="replace")
            parts.append(text)
            prev_cp = cp_end
        except Exception:
            break
    result = "".join(parts)
    cyr = sum(1 for c in result if "\u0400" <= c <= "\u04ff")
    if len(result) > 50 and cyr > len(result) * 0.05:
        return result
    return ""


def _scan_utf16_russian(wd: bytes) -> str:
    results = []
    i = 0
    while i < len(wd) - 3:
        b0, b1 = wd[i], wd[i + 1]
        if b0 == 0 or b1 != 0:
            i += 2
            continue
        code = struct.unpack_from("<H", wd, i)[0]
        if not _is_text_char(code):
            i += 2
            continue
        start = i
        cyr_count = 0
        total = 0
        j = i
        while j < len(wd) - 1:
            c = struct.unpack_from("<H", wd, j)[0]
            if c == 0:
                break
            if _is_text_char(c):
                if 0x0400 <= c <= 0x04FF:
                    cyr_count += 1
                total += 1
                j += 2
            else:
                break
        if total >= 15 and cyr_count >= 3:
            raw = wd[start:j]
            text = raw.decode("utf-16-le", errors="replace")
            results.append(text)
        i = j + 2 if j > i else i + 2
    return "".join(results)


def _scan_raw_ioc(wd: bytes) -> str:
    results = []
    latin_text = wd.decode("latin-1", errors="replace")
    utf16_text = wd.decode("utf-16-le", errors="replace")
    patterns = [
        r"\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}\[\.\]\d{1,3}",
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
        r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b",
        r"\b(?:[0-9a-f]{1,4}:){2,7}:?[0-9a-f]{1,4}\b",
        r"(?:[0-9a-f]{1,4}:){1,6}(?::[0-9a-f]{1,4}){1,6}",
        r"[a-fA-F0-9]{64}",
        r"[a-fA-F0-9]{40}",
        r"[a-fA-F0-9]{32}",
        r"[a-zA-Z0-9][a-zA-Z0-9\-]*(?:\[\.\][a-zA-Z0-9][a-zA-Z0-9\-]*)+",
        r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
        r"(?:BDU|БДУ)[:\s]*\d{4}-\d{3,6}",
        r"CVE-\d{4}-\d{4,7}",
    ]
    found = set()
    for text_source in [latin_text, utf16_text]:
        for pat in patterns:
            for m in re.finditer(pat, text_source):
                val = m.group(0)
                if val not in found and len(val) >= 7:
                    found.add(val)
                    results.append(val)
    return "\n".join(results)


def _is_text_char(c: int) -> bool:
    if (0x0400 <= c <= 0x04FF) or (0x0041 <= c <= 0x005A) or (0x0061 <= c <= 0x007A):
        return True
    if (0x00C0 <= c <= 0x00FF) or (0x0030 <= c <= 0x0039):
        return True
    if c in (
        0x0020, 0x002D, 0x002E, 0x002C, 0x003A, 0x003B, 0x0028, 0x0029,
        0x0022, 0x00AB, 0x00BB, 0x00A0, 0x000D, 0x000A, 0x0009,
        0x005B, 0x005D, 0x005C, 0x002F, 0x0040, 0x0023, 0x0021, 0x003F,
        0x002B, 0x003D, 0x003C, 0x003E, 0x0026, 0x0025, 0x0024, 0x007B,
        0x007D, 0x007E, 0x005F, 0x007C, 0x2116,
    ):
        return True
    return False


def _clean(text: str) -> str:
    return re.sub(r"\s+", " ", text.replace("\x00", "").replace("\r", " ")).strip()


def _fallback_scan(wd: bytes) -> str:
    scan = _scan_utf16_russian(wd)
    raw = _scan_raw_ioc(wd)
    return raw if len(raw) > len(scan) else scan