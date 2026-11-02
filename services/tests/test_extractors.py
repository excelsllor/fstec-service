from shared.extractor.ioc_extractor import extract_iocs
from shared.extractor.ner import extract_standard_ner
from shared.extractor.vuln_extractor import extract_vulns
from conftest import SAMPLE_TEXT


def test_ip_with_port():
    r = extract_iocs("Server IP: 203.0.113.10:8080")
    assert "203.0.113.10:8080" in r.ips


def test_ip_with_trailing_junk_char():
    r = extract_iocs("89.221.203.162l\n89.221.203.163;")
    assert "89.221.203.162" in r.ips
    assert "89.221.203.163" in r.ips


def test_ip_with_space_between_octets():
    r = extract_iocs("104 .238.149.198\n 45.59.104.152")
    assert "104.238.149.198" in r.ips
    assert "45.59.104.152" in r.ips


def test_ip_dedup_same_and_port_form():
    r = extract_iocs("5.101.88.7\n5.101.88.7\n103.27.108.55:48265\n103.27.108.55")
    assert r.ips.count("5.101.88.7") == 1
    assert "103.27.108.55:48265" in r.ips
    assert "103.27.108.55" in r.ips


def test_domain_with_port_stripped():
    r = extract_iocs("glowstickspro.com:1411\nstillpaving.com")
    assert "glowstickspro.com" in r.domains
    assert "stillpaving.com" in r.domains


def test_onion_domain_kept():
    r = extract_iocs("oifmtnublnj43db247fup2nrnr4uclfhm2nyoilpixzd73spj42fe4id.onion")
    assert "oifmtnublnj43db247fup2nrnr4uclfhm2nyoilpixzd73spj42fe4id.onion" in r.domains


def test_ipv4_cidr():
    r = extract_iocs("Сеть 10.0.0.0/24 заблокирована")
    assert r.ipv4_cidr == ["10.0.0.0/24"]
    assert "10.0.0.0" not in r.ips


def test_ipv6_full():
    r = extract_iocs("Версия IPv6: 2001:db8:0:0:0:0:0:1")
    assert "2001:db8:0:0:0:0:0:1" in r.ipv6
    assert r.ips == []


def test_ipv6_unspecified_ignored():
    r = extract_iocs('Сокет "::" в конфигурации')
    assert "::" not in r.ipv6


def test_obfuscated_domain():
    r = extract_iocs("C2 server: evil[.]com")
    assert "evil.com" in r.domains


def test_email_and_domain():
    r = extract_iocs("Contact: bad@evil.com")
    assert "bad@evil.com" in r.emails
    assert "evil.com" in r.domains


def test_obfuscated_email():
    r = extract_iocs("Письма с адреса info@fsb[.]msk[.]su необходимо ограничить")
    assert "info@fsb.msk.su" in r.emails


def test_cve_bdu():
    r = extract_iocs("BDU:2024-12345 соответствует CVE-2021-44228")
    assert "BDU:2024-12345" in r.vuln_ids
    assert "CVE-2021-44228" in r.cve_ids


def test_full_sample():
    r = extract_iocs(SAMPLE_TEXT)
    assert "203.0.113.10:8080" in r.ips
    assert "2001:db8:0:0:0:0:0:1" in r.ipv6
    assert "evil.com" in r.domains
    assert "bad@evil.com" in r.emails
    assert "BDU:2024-12345" in r.vuln_ids
    assert "CVE-2021-44228" in r.cve_ids


def test_ner_deadlines_and_contacts():
    ner = extract_standard_ner(SAMPLE_TEXT)
    assert any("3" in d and "дней" in d for d in ner.deadlines)
    assert any("до 01.06.2025" in d for d in ner.deadlines)
    assert any("".join(ch for ch in phone if ch.isdigit() or ch == "+") == "+79001234567"
               for phone in ner.contacts), "должен найти телефон +7 (900) 123-45-67"
    assert any(o == "ФСТЭК России" for o in ner.organizations)


def test_vuln_extractor_includes_patch_sentence():
    text = ("Хакерской группировкой Cloud Werewolf осуществляется эксплуатация уязвимости "
            "BDU:2024-12345 (CVE-2021-44228) в программном обеспечении Apache Log4j, уровень "
            "опасности по CVSS 9.8 — критический. Необходимо произвести обновление до версии "
            "2.17.0 до 01.06.2025.")
    vulns = extract_vulns(text)
    v = next((x for x in vulns if x.bdu_id == "BDU:2024-12345"), None)
    assert v is not None
    assert v.severity == "critical"
    assert "2.17.0" in v.description, "окно предложения должно включать фразу про патч"
    assert v.software.strip()  # Apache Log4j