"""Тесты: шаблонный проект ответа (библиотека мер + LLM/fallback-подбор)."""
import pytest

from shared.db import SessionLocal
from shared.generator.templated_reply import (
    _backfill_empty_blocks, _extract_ctx, _inflect_measure, _vuln_paragraph,
    _vulns_to_blocks, build_annotated_preview, generate_reply, load_reply_resources,
    persist_candidates, plan_reply, render_reply,
)
from shared.models import (
    Document, IntroFragment, Measure, MeasureCandidate,
    ReplyTemplate, Threat,
)


def test_vuln_paragraph_keeps_bdu_description_with_connected_adjective():
    vuln = {
        "bdu_id": "BDU:2026-07317",
        "software": "Samba",
        "severity": "critical",
        "cvss_version": "3.1",
        "description": (
            "Уязвимость подсистемы печати (printing subsystem) программ\n"
            "сетевого взаимодействия Samba (BDU:2026-07317, уровень опасности\n"
            "по CVSS 3.1 — критический), связанная с непринятием мер по нейтрализации\n"
            "специальных элементов при обработке параметра %J."
        ),
        "is_applicable": True,
        "cmdb_match": True,
        "action_type": "compensate",
        "recommendation": "Обновить ПО до указанной версии, закрывающей уязвимость",
    }
    line = _vuln_paragraph(vuln, "9-114")[0]
    assert "Уязвимость подсистемы печати" in line
    assert line.count("BDU:2026-07317") == 1
    assert "ведутся работы по обновлению подсистемы печати" in line


def _threat(db, doc, number, ttype, **kw):
    row = Threat(document_id=doc.id, number=number, threat_type=ttype,
                 theme=kw.get("theme", ""), group_name=kw.get("group_name", ""),
                 archive_name=kw.get("archive_name", ""), exe_name=kw.get("exe_name", ""),
                 malware_type=kw.get("malware_type", ""), description=kw.get("description", ""))
    db.add(row)
    return row


@pytest.fixture()
def doc_db():
    with SessionLocal() as db:
        doc = Document(source_filename="t.eml", letter_number="9/85",
                       letter_date="2026-04-29", letter_type="hacker")
        db.add(doc)
        db.flush()
        threats = [
            _threat(db, doc, 1, "phishing", theme="Договор",
                    group_name="Vortex Werewolf", archive_name="ishod.zip",
                    description="Фишинговая рассылка с архивом ishod.zip"),
            _threat(db, doc, 2, "malware_attack", group_name="NGC8211",
                    malware_type="DCRat",
                    description="Атака с применением трояна удаленного доступа (DCRat)"),
        ]
        db.commit()
        yield db, doc, threats
        db.close()


def test_seed_resources():
    with SessionLocal() as db:
        assert db.query(Measure).count() > 0
        assert db.query(IntroFragment).count() > 0
        tpls = {t.key for t in db.query(ReplyTemplate).all()}
        assert {"hacker", "compromise", "vulnerability", "other"} <= tpls


def test_fallback_plan_phishing(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, **{k: getattr(threats[0], k) for k in
               ("number", "threat_type", "theme", "group_name", "archive_name")}}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert plan["llm"] is False
    assert len(plan["blocks"]) == 1
    blk = plan["blocks"][0]
    assert "деятельностью хакерской группировки «Vortex Werewolf»" in blk["intro"]
    assert blk["measures"], "должны быть выбраны меры из библиотеки"


def test_render_no_double_number_no_duplicate(doc_db):
    db, doc, threats = doc_db
    _, _, tpl = load_reply_resources(db)
    blocks = [{"id": t.id, "number": t.number, "threat_type": t.threat_type,
               "theme": t.theme, "group_name": t.group_name,
               "archive_name": t.archive_name, "exe_name": "", "malware_type": "",
               "description": t.description} for t in threats]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    text, _ = render_reply(plan=plan, templates=tpl, letter_number="9/85",
                           letter_date="2026-04-29",
                           org_name="Правительства Липецкой области", addr_count=1)
    assert "1. 1." not in text
    assert "2. 2." not in text
    assert "связанных с связанных с" not in text
    assert "Ответ на письмо 9/85 от 29.04.2026" in text
    assert "Правительства Липецкой области" in text
    assert "С уважением" not in text
    assert text.count("\n1. В целях") >= 1
    assert "\n2. В целях" in text


def test_compromise_single_unnumbered_block(doc_db):
    db, doc, _ = doc_db
    doc.letter_type = "compromise"
    db.commit()
    blocks = [{"id": 0, "number": 1, "threat_type": "compromise", "theme": "",
               "group_name": "Орхидея", "archive_name": "", "exe_name": "",
               "malware_type": "", "description": "использование интернет-сайта"}]
    plan = plan_reply(db=db, letter_type="compromise", blocks=blocks,
                      addr_count=3, use_llm=False)
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/77", letter_date="2026-04-29",
                           org_name="Правительства Липецкой области", addr_count=3)
    assert "1. В целях" not in text
    assert "В целях предотвращения" in text
    assert "адресам" in text or "адресу" in text


def test_compromise_empty_blocks_fixed_header(doc_db):
    db, doc, _ = doc_db
    doc.letter_type = "compromise"
    db.commit()
    plan = plan_reply(db=db, letter_type="compromise", blocks=[], addr_count=1,
                      use_llm=False)
    assert plan["blocks"]
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-05-13",
                           org_name="Правительства Липецкой области", addr_count=1)
    assert "не подвержено риску" not in text
    assert "со случаем компрометации" in text
    assert "ограничение обращений" in text


def test_explicit_measures_override(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": ["Своя мера первая", "Своя мера вторая"]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert texts == ["Своя мера первая", "Своя мера вторая"]


def test_fragment_explicit_measures_do_not_override(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "description": "фишинг",
               "explicit_measures": [
                   "необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7",
                   "Обеспечить ограничение обращений к указанным адресам",
               ]}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks,
                      addr_count=1, use_llm=False)
    texts = [m["text"] for m in plan["blocks"][0]["measures"]]
    assert "необходимо реализовать меры защиты, указанные в пунктах 1.1-1.7" not in texts
    assert any("песочниц" in t for t in texts)


def test_generate_reply_plan_json_and_candidates(doc_db):
    from shared.generator.templated_reply import plan_reply as _p
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "archive_name": "ishod.zip", "exe_name": "", "malware_type": "",
               "description": "фишинг с архивом"}]
    plan = _p(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    plan["blocks"][0]["measures"].append(
        {"text": "новая мера от LLM;", "source": "new", "measure_id": None})
    rep = generate_reply(db, doc.id, letter_type="hacker", blocks=blocks, addr_count=1)
    assert rep["text"].startswith("Ответ на письмо 9/85")
    assert rep["docx"].startswith(b"PK")
    assert plan["llm"] is False
    ids = persist_candidates(db, doc.id, [{"text": "новая мера от LLM;",
                                           "note": "тест", "threat_id": threats[0].id}])
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == ids[0]).first()
    assert c.status == "pending"
    ann = build_annotated_preview(db, plan, blocks, addr_count=1)
    assert ann[0]["measure_annotations"][-1]["source"] == "new"
    assert ann[0]["section_text"].startswith("1. В целях")
    # обратная совместимость для редактора ответа: measure_options/base_measures обязательны
    assert ann[0]["measure_options"]
    assert ann[0]["base_measures"]
    assert "новая мера от LLM;" in ann[0]["measure_options"]
    assert "новая мера от LLM;" not in ann[0]["base_measures"]


def test_accept_candidate_adds_to_library(doc_db):
    from datetime import datetime, timezone
    db, doc, _ = doc_db
    c = MeasureCandidate(document_id=doc.id, text="одобренная мера;", note="")
    db.add(c)
    db.commit()
    with SessionLocal() as admin_db:
        row = admin_db.query(MeasureCandidate).filter(MeasureCandidate.id == c.id).first()
        row.status = "approved"
        row.reviewed_at = datetime.now(timezone.utc)
        admin_db.flush()
        if not admin_db.query(Measure).filter(Measure.text == row.text).first():
            admin_db.add(Measure(text=row.text, threat_type="",
                                 tags="", addr_inflection=False, source="llm"))
        admin_db.commit()
        assert admin_db.query(Measure).filter(Measure.text == "одобренная мера;").count() == 1


def test_gateway_admin_and_generate(client, doc_db):
    from conftest import headers
    db, doc, threats = doc_db
    doc.letter_type = "hacker"
    db.commit()
    h = headers(client)
    r = client.post("/admin/measures", json={"text": "контролируемая тестовая мера;"},
                    headers=h)
    assert r.status_code == 200
    r = client.get("/admin/measures", headers=h)
    assert r.status_code == 200
    texts = [m["text"] for m in r.json()]
    assert "контролируемая тестовая мера;" in texts

    # генерация через gateway (threat уже в БД)
    r = client.post("/reply/generate", params={"doc_id": doc.id}, headers=h)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "generated" and "Ответ на письмо 9/85" in body["text"]

    # кандидат → accept добавляет в библиотеку
    from shared.models import MeasureCandidate
    with SessionLocal() as s:
        c = MeasureCandidate(document_id=doc.id, threat_id=threats[0].id,
                             text="кандидатская тестовая мера;", note="", status="pending")
        s.add(c)
        s.commit()
        cid = c.id
    r = client.post(f"/admin/measures/candidates/{cid}/accept", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "approved"
    with SessionLocal() as s:
        assert s.query(Measure).filter(Measure.text == "кандидатская тестовая мера;").count() == 1
        c = s.query(MeasureCandidate).filter(MeasureCandidate.id == cid).first()
        assert c.status == "approved"
    r = client.post(f"/admin/measures/candidates/{cid}/reject", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "rejected"
    assert client.get("/admin/measures/candidates", params={"status": "pending"}, headers=h).status_code == 200


def test_inflection_addr_singular_plural(doc_db):
    db, doc, threats = doc_db
    blocks = [{"id": threats[0].id, "number": 1, "threat_type": "phishing",
               "theme": "Договор", "group_name": "Vortex Werewolf",
               "description": "фишинг"}]
    p_one = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    p_many = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=4, use_llm=False)
    m1 = " ".join(m["text"] for m in p_one["blocks"][0]["measures"])
    mN = " ".join(m["text"] for m in p_many["blocks"][0]["measures"])
    assert "к указанному адресу" in m1
    assert "к указанным адресам" in mN


def test_malware_types_extraction_9_70(doc_db):
    """«возможно применение … типов «червь» (CMoon) и «стилер» (WhiteSnake)» (9-70)."""
    db, doc, _ = doc_db
    desc = ("Хакерской группировкой «White Werewolf» возможно применение вредоносного "
            "программного обеспечения типов «червь» (CMoon) и «стилер» (WhiteSnake).")
    blocks = [{"id": 0, "number": 1, "threat_type": "malware_attack",
               "group_name": "White Werewolf", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    intro = plan["blocks"][0]["intro"]
    assert "«червь» (CMoon) и «стилер» (WhiteSnake)" in intro
    assert "White Werewolf" in intro


def test_vuln_exploit_priority_9_70(doc_db):
    """Эксплуатация уязвимости → intro vuln_exploit с функцией + BDU + CVSS."""
    db, doc, _ = doc_db
    desc = ("Осуществляется эксплуатация уязвимости функции requireModule() пакетов "
            "react-server-dom-webpack JavaScript библиотеки построения пользовательских "
            "интерфейсов React (BDU:2025-15156, уровень опасности по CVSS 3.1 - критический).")
    blocks = [{"id": 0, "number": 2, "threat_type": "malware_attack", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    blk = plan["blocks"][0]
    assert blk["fragment_key"] == ""
    assert "requireModule()" in blk["intro"]
    assert "BDU:2025-15156" in blk["intro"]
    assert "критический" in blk["intro"]


def test_vuln_block_patch_tail(doc_db):
    """Vulnerability-угроза в hacker-письме: intro содержит фразу про обновление (тест pipeline)."""
    db, doc, _ = doc_db
    desc = ("Осуществляется эксплуатация уязвимости BDU:2024-12345 (CVE-2021-44228) "
            "в программном обеспечении Apache Log4j, уровень опасности по CVSS 9.8 — критический. "
            "Необходимо произвести обновление до версии 2.17.0 до 01.06.2025.")
    blocks = [{"id": 0, "number": 1, "threat_type": "vulnerability", "description": desc}]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    intro = plan["blocks"][0]["intro"]
    assert "BDU:2024-12345" in intro
    assert "обновление до версии" not in intro


def test_measure_variance_repetitive_blocks(doc_db):
    db, doc, _ = doc_db
    desc = ("Осуществляется рассылка вредоносного программного обеспечения; "
            "необходимо ограничить обращения к адресам.")
    blocks = [{"id": 0, "number": i, "threat_type": "malware_attack", "description": desc}
              for i in range(1, 5)]
    plan = plan_reply(db=db, letter_type="hacker", blocks=blocks, addr_count=1, use_llm=False)
    from shared.generator.templated_reply import load_reply_resources
    core_n = len([m for m in load_reply_resources(db)[0]
                  if "core" in (m.get("tags") or "")])
    assert core_n >= 8, "ядровый набор мер должен быть собран"
    assert len(plan["blocks"][0]["measures"]) == core_n, "полный core — в первом блоке"
    assert len(plan["blocks"][1]["measures"]) < core_n, "повторы не дублируют весь core"
    unique = {m["text"] for b in plan["blocks"] for m in b["measures"]}
    assert unique, "уникальные меры не должны потеряться"


def test_vuln_not_in_cmdb_says_not_used(doc_db):
    """ПО отсутствует в БД заказчика (cmdb_match=False) → «не используется»."""
    db, doc, _ = doc_db
    vulns = [{
        "bdu_id": "BDU:2026-10166",
        "description": ("Уязвимость компонента WebView HTTP Server программного средства "
                        "управления и запуска OCI-контейнеров Podman связана с неконтролируемым "
                        "расходом ресурсов."),
        "software": "управления и запуска OCI-контейнеров Podman",
        "severity": "critical", "cvss_score": 9.8, "cmdb_match": False,
    }]
    text, _ = render_reply(plan={"template_key": "vulnerability", "blocks": [], "llm": False},
                           templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-07-24",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Программное средство управления и запуска OCI-контейнеров Podman не используется." in text
    assert "ведутся работы по обновлению" not in text


def test_vuln_in_cmdb_uses_update(doc_db):
    db, doc, _ = doc_db
    vulns = [{
        "bdu_id": "BDU:2026-10166",
        "description": ("Уязвимость компонента WebView HTTP Server программного средства "
                        "управления и запуска OCI-контейнеров Podman связана с неконтролируемым "
                        "расходом ресурсов."),
        "software": "управления и запуска OCI-контейнеров Podman",
        "severity": "critical", "cvss_score": 9.8, "cmdb_match": True,
    }]
    text, _ = render_reply(plan={"template_key": "vulnerability", "blocks": [], "llm": False},
                           templates=load_reply_resources(db)[2],
                           letter_number="9/999", letter_date="2026-07-24",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "ведутся работы по обновлению" in text
    assert "не используется" not in text


def test_vuln_render_paragraph(doc_db):
    """Vulnerability-письмо: абзац по эталону «Уязвимость <продукт> (BDU:…), связанная с …»."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    vulns = [{
        "bdu_id": "BDU:2026-07317",
        "cve_id": "CVE-2026-1111",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по обеспечению "
                        "целостности программного обеспечения. Уровень опасности по CVSS 3.1 — "
                        "критический."),
        "software": "Samba",
        "severity": "critical",
        "cvss_score": 9.8,
        "fixed_version": "",
        "patch_url": "",
        "recommendation": "обновить Samba",
    }]
    plan = {"template_key": "vulnerability", "blocks": [], "llm": False}
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/114", letter_date="2026-06-10",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Уязвимость подсистемы печати (printing subsystem) программ сетевого" in text
    assert "BDU:2026-07317" in text
    assert "CVE-2026-1111" not in text
    assert "уровень опасности по CVSS 3.1 — критический" in text
    assert ", связанная с непринятием мер" in text
    assert "С уважением" not in text


def test_vuln_letter_llm_plan_blocks(doc_db):
    """Vulnerability-письмо: уязвимость → LLM-блок (меры из плана), абзац без
    хвоста «Эксплуатация уязвимости…», формат «уровень опасности по CVSS {v} — {sev}»."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    from shared.generator.templated_reply import _apply_llm_plan
    vulns = [{
        "bdu_id": "BDU:2026-07317", "cve_id": "CVE-2026-4480",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по нейтрализации "
                        "специальных элементов при обработке параметра %J. Уровень опасности по "
                        "CVSS 3.1 — критический. Эксплуатация уязвимости "
                        "может позволить нарушителю, действующему удаленно, выполнить произвольный код"),
        "software": "Samba", "severity": "critical", "cvss_score": 10.0,
        "cvss_version": "", "recommendation": "Обновить Samba",
    }]
    blocks = _vulns_to_blocks(vulns)
    assert blocks[0]["threat_type"] == "vulnerability"
    assert blocks[0]["n"] == 1 and blocks[0]["bdu_id"] == "BDU:2026-07317"
    library, fragments, tpl = load_reply_resources(db)
    lib_by_id = {m["id"]: m for m in library}
    frag_by_key = {f["key"]: f for f in fragments}
    # id мер не хардкодим: библиотека пересобирается из эталонов, порядок/id меняются.
    base_id = next(m["id"] for m in library if "base" in (m["tags"] or ""))
    phish_id = next(m["id"] for m in library if m["threat_type"] == "phishing")
    llm_plan = {"template_key": "vulnerability", "blocks": [
        {"n": 1, "fragment_id": "", "measure_ids": [phish_id, base_id], "new_measures": [
            {"text": "Контроль применения обновлений Samba;", "note": ""}]}]}
    plan = _apply_llm_plan(llm_plan, lib_by_id, frag_by_key, blocks, addr_count=1)
    assert plan and plan["llm"] is True
    blk = plan["blocks"][0]
    assert blk["software"] == "Samba"  # cvss_version из описания подставляется на рендере
    assert len(blk["measures"]) == 2  # base-мера + new_measure; phishing-мера отсечена
    assert blk["measures"][0]["measure_id"] == base_id
    text, _ = render_reply(plan=plan, templates=tpl, letter_number="9/114",
                           letter_date="2026-06-10",
                           org_name="Правительства Липецкой области",
                           active_vulns=vulns, addr_count=1)
    assert "Эксплуатация уязвимости может позволить" not in text
    assert "CVE-2026-4480" not in text
    assert "уровень опасности по CVSS 3.1 — критический" in text
    assert "Уязвимость подсистемы печати (printing subsystem)" in text
    assert "связанная с непринятием мер" in text
    assert "Дополнительно приняты следующие меры:" not in text
    assert "Контроль применения обновлений Samba;" not in text
    assert "ведутся работы по обновлению" in text


def test_vuln_letter_fallback_still_bdu(doc_db):
    """LLM недоступен → vuln-план пустой, рендер остаётся на BDU-описаниях."""
    db, doc, _ = doc_db
    doc.letter_type = "vulnerability"
    db.commit()
    vulns = [{
        "bdu_id": "BDU:2026-07317", "cve_id": "CVE-2026-4480",
        "description": ("Уязвимость подсистемы печати (printing subsystem) программ сетевого "
                        "взаимодействия Samba связана с непринятием мер по нейтрализации "
                        "специальных элементов при обработке параметра %J."),
        "software": "Samba", "severity": "critical", "cvss_score": 10.0,
        "cvss_version": "3.1", "recommendation": "",
    }]
    blocks = _vulns_to_blocks(vulns)
    plan = plan_reply(db=db, letter_type="vulnerability", blocks=blocks,
                      addr_count=1, use_llm=False)
    assert plan["blocks"] == [] and plan["llm"] is False
    text, _ = render_reply(plan=plan, templates=load_reply_resources(db)[2],
                           letter_number="9/114", letter_date="2026-06-10",
                           org_name="Правительства Липецкой области", active_vulns=vulns)
    assert "Уязвимость подсистемы печати" in text
    assert "BDU:2026-07317" in text


def test_backfill_empty_llm_measures(doc_db):
    """Пустой measure_ids от LLM (как у 9B) → блок заполняется fallback-мерами."""
    db, doc, threats = doc_db
    library, _, _ = load_reply_resources(db)
    plan = {"template_key": "hacker", "llm": True, "blocks": [
        {"number": 1, "threat_id": threats[0].id, "fragment_key": "phishing_general",
         "intro": "деятельностью хакерской группировки Vortex Werewolf",
         "threat_type": "phishing", "description": threats[0].description,
         "measures": [], "new_measures": []},
        {"number": 2, "threat_id": threats[1].id, "fragment_key": "",
         "intro": "реализуемыми угрозами безопасности информации",
         "threat_type": "malware_attack", "description": "атака с DCRat",
         "measures": [], "new_measures": []},
    ]}
    _backfill_empty_blocks(plan, "hacker", addr_count=1, library=library)
    blk0 = plan["blocks"][0]
    blk1 = plan["blocks"][1]
    assert blk0["measures"], "фишинг-блок обязан получить антифишинговый набор"
    assert any("песочниц" in m["text"] for m in blk0["measures"])
    assert blk1["measures"], "не-фишинг блок обязан получить базовые меры"
    assert all(m["source"] == "library" for m in blk0["measures"] + blk1["measures"])

def test_software_placeholder_substituted():
    """Шаблон «{{software}} не применяется» -> продукт из блока уязвимости."""
    blk = {"threat_type": "vulnerability", "software": "Samba",
           "description": "Уязвимость подсистемы печати Samba (BDU:2026-07317)"}
    assert _extract_ctx(blk)["software"] == "Samba"
    out = _inflect_measure("{{software}} не применяется", 1, "Samba")
    assert out == "Samba не применяется"
    assert "{{" not in out


def test_software_placeholder_fallback_without_product():
    """Без продукта подставляем нейтральную формулировку, а не оставляем {{...}}:
    неразрешённые плейсхолдеры вырезаются из письма фильтром ниже по коду."""
    out = _inflect_measure("{{software}} не применяется", 1, "")
    assert "{{" not in out
    assert "не применяется" in out


def test_software_placeholder_in_llm_plan(doc_db):
    """Мера из библиотеки с плейсхолдером доходит до плана уже с продуктом."""
    db, doc, _ = doc_db
    library, _, _ = load_reply_resources(db)
    tpl = next((m for m in library
                if "{{software}}" in (m["text"] or "")
                and (m.get("threat_type") == "vulnerability")), None)
    if tpl is None:
        pytest.skip("в библиотеке нет шаблонных vulnerability-мер")
    blocks = [{"id": 0, "n": 1, "threat_type": "vulnerability",
               "software": "OpenSSL",
               "description": "Уязвимость библиотеки OpenSSL (BDU:2021-00364)"}]
    lib_by_id = {m["id"]: m for m in library}
    llm_plan = {"template_key": "vulnerability", "blocks": [
        {"n": 1, "fragment_id": "", "measure_ids": [tpl["id"]], "new_measures": []}]}
    from shared.generator.templated_reply import _apply_llm_plan
    out = _apply_llm_plan(llm_plan, lib_by_id, {}, blocks, 1)
    texts = [m["text"] for m in out["blocks"][0]["measures"]]
    assert texts, "LLM-выбранная шаблонная мера должна попасть в план"
    assert all("{{" not in t for t in texts)
    assert any("OpenSSL" in t for t in texts)
