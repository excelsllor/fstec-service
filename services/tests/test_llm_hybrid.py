"""Пакет A: гибрид regex+LLM и NER «ПО+версия» — детерминированные части."""
from llm_service.provider import _mentions as mentions, _norm_ip as norm_ip
from shared.extractor.vuln_extractor import _extract_version as version


def test_mentions_literal_and_obfuscated():
    assert mentions("домен evil.com и ip 10.0.0.1", "evil.com")
    assert mentions("104[.]238[.]149[.]198", "104.238.149.198")
    assert mentions("hxxps[:]//bull-run[.]fun", "bull-run.fun")
    assert not mentions("текст без адресов", "evil.com")


def test_mentions_whitespace_split_hash():
    text = "хэш 5a6457\n658597 09eb382e\nf1ad588b 10c996bb4bec689230a6ac6ff455b052889"
    assert mentions(text, "5a645765859709eb382ef1ad588b10c996bb4bec689230a6ac6ff455b052889")


def test_mentions_rejects_fabricated():
    assert not mentions("настоящий текст письма", "104.238.149.198")


def test_norm_ip():
    assert norm_ip("104.238.149.198") == "104.238.149.198"
    assert norm_ip("2001:db8::1") == "2001:db8::1"
    assert norm_ip("999.1.1.1") is None
    assert norm_ip("not-an-ip") is None


def test_version_from_patch_sentence():
    assert version("необходимо обновление до версии 2.17.0") == "2.17.0"
    assert version("в версии 4.x") == "4.x"


def test_version_ignores_cvss():
    assert version("уровень опасности по CVSS 9.8 — критический") == ""