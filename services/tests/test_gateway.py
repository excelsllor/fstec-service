"""API Gateway: bootstrap-auth, upload, документы, отчёты, reply (ТЗ 2.6)."""
import io
import os
from pathlib import Path

os.environ.setdefault("FSTEC_EVENT_BUS", "memory")

import pytest
from conftest import headers, make_docx_bytes


def _headers(client):
    return headers(client)


def test_login_and_status(client):
    # bootstrap-администратор уже вошёл в фикстуре → первичная настройка завершена
    assert client.get("/api/auth/status").json()["needs_setup"] is False
    me = client.get("/api/auth/me", headers=_headers(client))
    assert me.status_code == 200
    assert me.json()["role"] == "admin"


def test_unauthorized(client):
    assert client.get("/documents").status_code == 401


def test_upload_and_pipeline(client):
    files = {"files": ("letter.docx", make_docx_bytes(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
    r = client.post("/upload", files=files, headers=_headers(client))
    assert r.status_code == 201, r.text
    doc_id = r.json()["id"]

    doc = client.get(f"/documents/{doc_id}", headers=_headers(client))
    assert doc.status_code == 200
    data = doc.json()
    assert data["processing_stage"] == "done"
    assert data["status"] == "completed"
    assert data["letter_type"] == "hacker"
    assert data["ioc_count"] >= 4
    assert data["vuln_count"] >= 1

    listing = client.get("/documents", headers=_headers(client))
    assert listing.status_code == 200
    assert any(d["id"] == doc_id for d in listing.json())

    reports = client.get(f"/reports/{doc_id}/download", headers=_headers(client))
    assert reports.status_code == 200
    assert reports.content[:2] == b"PK"
    assert reports.headers["content-disposition"].startswith("attachment")

    raw = client.get(f"/reports/{doc_id}/download_raw", headers=_headers(client))
    assert raw.status_code == 200
    assert raw.headers["content-disposition"].startswith("attachment")

    reply = client.post(f"/reply/generate?doc_id={doc_id}", headers=_headers(client))
    assert reply.status_code == 200
    assert "обновление" in reply.json()["text"].lower()


def test_legacy_compat(client):
    listing = client.get("/api/letters", headers=_headers(client))
    assert listing.status_code == 200
    stats = client.get("/api/letters/stats", headers=_headers(client))
    assert stats.status_code == 200
    assert stats.json()["total_letters"] >= 1


def test_duplicate_upload_returns_cached_document(client):
    content = make_docx_bytes("Уникальный тест дедупликации SHA-256 2026-10-24")
    files = {"files": ("dup.docx", content, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")}
    first = client.post("/upload", files=files, headers=_headers(client))
    assert first.status_code == 201
    doc_id = first.json()["id"]
    second = client.post("/upload", files={
        "files": ("dup-copy.docx", content, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    }, headers=_headers(client))
    assert second.status_code == 201
    body = second.json()
    assert body["id"] == doc_id
    assert body.get("duplicate") is True


def test_upload_rejects_bad_extension(client):
    files = {"files": ("evil.exe", b"MZ", "application/x-msdownload")}
    r = client.post("/upload", files=files, headers=_headers(client))
    assert r.status_code == 415


def _first_doc_id(client):
    listing = client.get("/documents", headers=_headers(client))
    docs = listing.json()
    if docs:
        return docs[0]["id"]
    from conftest import create_uploaded_document
    return create_uploaded_document(Path(__import__("tempfile").mkdtemp()))


def test_document_detail_arrays(client):
    doc_id = _first_doc_id(client)
    data = client.get(f"/documents/{doc_id}", headers=_headers(client)).json()
    assert isinstance(data["attachments"], list) and data["attachments"]
    assert isinstance(data["threats"], list)
    assert isinstance(data["iocs"], list)
    assert isinstance(data["vulnerabilities"], list)
    assert "response" in data
    assert data["ioc_count"] == len(data["iocs"])


def test_reply_preview_and_response(client):
    doc_id = _first_doc_id(client)
    preview = client.get(f"/api/letters/{doc_id}/response/preview", headers=_headers(client))
    assert preview.status_code == 200
    body = preview.json()
    assert body["title"]
    assert isinstance(body["sections"], list)
    # обратная совместимость для фронтенда: секции обязаны содержать measure_options/base_measures
    for sec in body["sections"]:
        assert "measure_options" in sec
        assert "base_measures" in sec

    text = client.get(f"/api/letters/{doc_id}/response/text", headers=_headers(client)).json()
    assert "exists" in text

    upd = client.put(f"/api/letters/{doc_id}/response", json={"content": "Тестовый ответ"}, headers=_headers(client))
    assert upd.status_code == 200
    assert "Тестовый ответ" in client.get(f"/api/letters/{doc_id}/response/text", headers=_headers(client)).json()["text"]


def test_export_iocs_endpoints(client):
    doc_id = _first_doc_id(client)
    for exp_type in ("emails", "ip_addresses", "domains", "ioc_indicators"):
        r = client.get(f"/api/letters/{doc_id}/export/{exp_type}", headers=_headers(client))
        assert r.status_code == 200
        d = client.get(f"/api/letters/{doc_id}/export/{exp_type}/docx", headers=_headers(client))
        assert d.status_code == 200
        assert d.content[:2] == b"PK"
    bad = client.get(f"/api/letters/{doc_id}/export/nope", headers=_headers(client))
    assert bad.status_code == 400


def test_ioc_manual_crud(client):
    doc_id = _first_doc_id(client)
    bad = client.post(f"/api/letters/{doc_id}/iocs", json={"value": "x", "ioc_type": "bogus"},
                      headers=_headers(client))
    assert bad.status_code == 400

    created = client.post(f"/api/letters/{doc_id}/iocs",
                          json={"value": "manual.example", "ioc_type": "domain"},
                          headers=_headers(client))
    assert created.status_code == 200, created.text
    ioc = next(i for i in created.json()["iocs"] if i["value"] == "manual.example")
    assert ioc["ioc_type"] == "domain"

    updated = client.put(f"/api/letters/{doc_id}/iocs/{ioc['id']}",
                         json={"value": "manual2.example"}, headers=_headers(client))
    assert updated.status_code == 200
    assert any(i["value"] == "manual2.example" for i in updated.json()["iocs"])

    deleted = client.delete(f"/api/letters/{doc_id}/iocs/{ioc['id']}", headers=_headers(client))
    assert deleted.status_code == 200
    assert all(i["id"] != ioc["id"] for i in deleted.json()["iocs"])


def test_templates_admin_endpoints(client):
    """CRUD для шаблонов и библиотеки мер (страница «Шаблоны»)."""
    import uuid
    h = _headers(client)
    r = client.get("/api/templates/threat-types", headers=h)
    assert r.status_code == 200

    key = f"t_{uuid.uuid4().hex[:8]}"
    r = client.post("/api/templates/threat-types", headers=h,
                    json={"name": f"Тест {key}", "key": key, "description": "для теста"})
    assert r.status_code == 201, r.text
    tt_id = r.json()["id"]

    r = client.put(f"/api/templates/threat-types/{tt_id}", headers=h,
                   json={"name": f"Тест {key} (изменён)", "description": ""})
    assert r.status_code == 200
    assert r.json()["name"] == f"Тест {key} (изменён)"

    # библиотека мер (MeasureTemplate: content хранит меры построчно)
    r = client.post("/api/templates/measure-templates", headers=h,
                    json={"name": f"Блок {key}", "threat_type_id": tt_id,
                          "measures": "мера один;\nмера два;", "is_default": True})
    assert r.status_code == 201, r.text
    mt_id = r.json()["id"]
    assert r.json()["measures"] == "мера один;\nмера два;"

    r = client.put(f"/api/templates/measure-templates/{mt_id}", headers=h,
                   json={"is_default": False, "threat_type_id": tt_id})
    assert r.status_code == 200
    assert r.json()["is_default"] is False

    r = client.post("/api/templates/vuln-templates", headers=h,
                    json={"name": f"ВЛ {key}", "action_type": "update",
                          "content": "обновить {software};", "is_default": False})
    assert r.status_code == 201, r.text
    vt_id = r.json()["id"]

    r = client.get("/api/templates/vuln-templates", headers=h)
    assert r.status_code == 200
    assert any(t["id"] == vt_id for t in r.json())

    assert client.delete(f"/api/templates/vuln-templates/{vt_id}", headers=h).status_code == 200
    assert client.delete(f"/api/templates/measure-templates/{mt_id}", headers=h).status_code == 200
    assert client.delete(f"/api/templates/threat-types/{tt_id}", headers=h).status_code == 200


def test_diagnostics_requires_admin(client):
    """Диагностика доступна только администратору."""
    assert client.get("/api/diagnostics").status_code == 401
