"""Аудит-регрессия: XXE-гард ZIP-XML, строгий TLS у BDU, rate-limit логина, orgname-дефолт."""

import io
import zipfile

import httpx
import pytest

from shared.parsers import parse_file
from shared.parsers.docx_parser import parse_docx
from shared.parsers.xlsx_parser import parse_xlsx
from tests.formats import make_docx_bytes, make_xlsx_bytes

_XXE = b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'


def _docx_with_xxe() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>")
        zf.writestr("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>")
        zf.writestr("word/document.xml", _XXE + b"<w:document/>")
    return buf.getvalue()


def _xlsx_with_xxe() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", b"<?xml version=\"1.0\"?><Types/>")
        zf.writestr("_rels/.rels", b"<?xml version=\"1.0\"?><Relationships/>")
        zf.writestr("xl/workbook.xml", _XXE + b"<workbook/>")
    return buf.getvalue()


def test_docx_xxe_blocked():
    res = parse_docx(_docx_with_xxe())
    assert not res.text
    assert any("отклонён" in e or "DOCTY" in e for e in res.errors)


def test_xlsx_xxe_blocked():
    res = parse_xlsx(_xlsx_with_xxe())
    assert not res.text
    assert any("отклонён" in e for e in res.errors)


def test_parse_file_docx_xxe_blocked(tmp_path):
    p = tmp_path / "bad.docx"
    p.write_bytes(_docx_with_xxe())
    res = parse_file(p)
    assert not res.text
    assert any("отклонён" in e for e in res.errors)


def test_normal_docx_xlsx_still_parsed():
    r1 = parse_docx(make_docx_bytes())
    assert "CVE-2021-44228" in r1.text
    r2 = parse_xlsx(make_xlsx_bytes())
    assert "CVE-2021-44228" in r2.text


def test_login_rate_limit(monkeypatch):
    from api_gateway import main as gw
    monkeypatch.setattr(gw, "_LOGIN_LIMIT_DISABLED", False)
    monkeypatch.setattr(gw, "_LOGIN_LIMIT", 2)
    monkeypatch.setattr(gw, "_LOGIN_WINDOW_S", 60)
    ip = "10.9.9.9"
    assert gw._login_allowed(ip) is True
    assert gw._login_allowed(ip) is True
    assert gw._login_allowed(ip) is False


def test_bdu_tls_strict_no_verify_fallback_by_default(monkeypatch):
    from security_service import bdu_client
    monkeypatch.setattr(bdu_client, "BDU_TLS_INSECURE_FALLBACK", False)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ConnectError("CERTIFICATE_VERIFY_FAILED certificate verify failed")

    client = bdu_client.BDUClient(
        cache=bdu_client.MemoryCache(),
        transport=httpx.MockTransport(handler))
    with pytest.raises(httpx.TransportError):
        import asyncio
        asyncio.run(client._fetch("2021-1234"))
    assert calls["n"] == 1


def test_bdu_tls_fallback_only_when_flag_on(monkeypatch):
    from security_service import bdu_client
    monkeypatch.setattr(bdu_client, "BDU_TLS_INSECURE_FALLBACK", True)
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        raise httpx.ConnectError("CERTIFICATE_VERIFY_FAILED certificate verify failed")

    client = bdu_client.BDUClient(
        cache=bdu_client.MemoryCache(),
        transport=httpx.MockTransport(handler))
    import asyncio
    with pytest.raises(httpx.TransportError):
        asyncio.run(client._fetch("2021-1234"))
    assert calls["n"] == 2


def test_org_name_default_is_target():
    from shared.config import ORG_NAME
    from shared.generator.templated_reply import render_reply
    assert ORG_NAME == "Правительства Липецкой области"
    plan = {"template_key": "hacker", "blocks": [
        {"intro": "угроз тест", "measures": [{"text": "мера;"}]}]}
    text, _ = render_reply(plan=plan, letter_number="9/1", letter_date="01.01.2026")
    assert "инфраструктуры Правительства Липецкой области" in text