"""Admin/API контуры: CRUD пользователей (ТЗ 5), защита последнего админа,
мягкое удаление писем, одноразовый bootstrap-экран."""
from conftest import create_uploaded_document, headers
from shared.config import BOOTSTRAP_USERNAME
from shared.db import SessionLocal
from shared.models import BootstrapSecret, Document


def test_users_crud_and_guards(client):
    H = headers(client)
    r = client.post("/api/users", json={"username": "op1", "password": "secret1",
                                        "role": "user", "full_name": "Оператор"},
                    headers=H)
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    assert r.json()["created_at"]

    assert client.post("/api/users", json={"username": "op1", "password": "secret1"},
                       headers=H).status_code == 409
    assert client.post("/api/users", json={"username": "op2", "password": "123"},
                       headers=H).status_code == 400
    assert client.post("/api/users", json={"username": "op3", "password": "secret1",
                                           "role": "root"}, headers=H).status_code == 400

    usernames = [u["username"] for u in client.get("/api/users", headers=H).json()]
    assert "op1" in usernames

    r = client.put(f"/api/users/{uid}", json={"full_name": "Оператор 2", "is_active": False},
                   headers=H)
    assert r.status_code == 200
    assert r.json()["full_name"] == "Оператор 2" and r.json()["is_active"] is False

    assert client.post("/api/auth/login", json={"username": "op1",
                                                "password": "secret1"}).status_code == 401
    r = client.put(f"/api/users/{uid}", json={"password": "secret2", "is_active": True},
                   headers=H)
    assert r.status_code == 200
    assert client.post("/api/auth/login", json={"username": "op1",
                                                "password": "secret2"}).status_code == 200

    r = client.delete(f"/api/users/{uid}", headers=H)
    assert r.status_code == 200 and r.json()["deleted"] is True
    usernames = [u["username"] for u in client.get("/api/users", headers=H).json()]
    assert "op1" not in usernames


def test_users_deactivate_when_owns_documents(client, tmp_path):
    H = headers(client)
    uid = client.post("/api/users", json={"username": "op4", "password": "secret1"},
                      headers=H).json()["id"]
    doc_id = create_uploaded_document(tmp_path)
    with SessionLocal() as db:
        db.query(Document).filter(Document.id == doc_id).update({"created_by": uid})
        db.commit()
    r = client.delete(f"/api/users/{uid}", headers=H)
    assert r.status_code == 200 and r.json()["deactivated"] is True
    users = {u["id"]: u for u in client.get("/api/users", headers=H).json()}
    assert users[uid]["is_active"] is False


def test_users_require_admin(client):
    assert client.get("/api/users").status_code == 401
    H = headers(client)
    client.post("/api/users", json={"username": "op5", "password": "secret1"}, headers=H)
    token = client.post("/api/auth/login", json={"username": "op5",
                                                 "password": "secret1"}).json()["access_token"]
    r = client.get("/api/users", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 403


def test_last_admin_protection(client):
    H = headers(client)
    me = client.get("/api/auth/me", headers=H).json()
    assert me["created_at"]
    assert client.put(f"/api/users/{me['id']}", json={"is_active": False},
                      headers=H).status_code == 400
    assert client.put(f"/api/users/{me['id']}", json={"role": "user"},
                      headers=H).status_code == 400
    assert client.delete(f"/api/users/{me['id']}", headers=H).status_code == 400


def test_delete_letter_soft(client, tmp_path):
    H = headers(client)
    doc_id = create_uploaded_document(tmp_path)
    before = client.get("/api/letters/stats", headers=H).json()["total_letters"]
    r = client.delete(f"/api/letters/{doc_id}", headers=H)
    assert r.status_code == 200 and r.json()["status"] == "deleted"
    ids = [d["id"] for d in client.get("/api/letters", headers=H).json()]
    assert doc_id not in ids
    assert client.get("/api/letters/stats", headers=H).json()["total_letters"] == before - 1
    r2 = client.delete(f"/api/letters/{doc_id}", headers=H)
    assert r2.status_code == 200 and r2.json()["status"] == "deleted"


def test_bootstrap_status_once(client):
    with SessionLocal() as db:
        db.query(BootstrapSecret).delete()
        db.add(BootstrapSecret(username=BOOTSTRAP_USERNAME, secret="x", used=False))
        db.commit()
    js = client.get("/api/auth/status").json()
    assert js["needs_setup"] is True
    assert js["bootstrap_username"] == BOOTSTRAP_USERNAME
    assert "bootstrap_password" not in js
    assert js["bootstrap_source"] == "file"
    with SessionLocal() as db:
        db.query(BootstrapSecret).delete()
        db.add(BootstrapSecret(username=BOOTSTRAP_USERNAME, secret="x", used=True))
        db.commit()
    js = client.get("/api/auth/status").json()
    assert js["needs_setup"] is False
    assert "bootstrap_password" not in js
