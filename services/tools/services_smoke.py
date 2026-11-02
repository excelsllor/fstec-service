"""HTTP-смоук локального E2E (микросервисы, SQLite-шина).

Запуск (после run_local.ps1 / run_local.sh):
    cd services
    python tools/services_smoke.py

Сценарий: bootstrap-админ (dev) → upload → документ проходит
uploaded → parsed → analyzed → assessed → completed; проверяются
source/cmdb_match у уязвимостей, SLA, карточка индикаторов и ответ.
"""
import argparse
import io
import os
import sys
import time
from pathlib import Path

_SERVICES = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_SERVICES))

# окружение до импорта shared.*
os.environ.setdefault("FSTEC_EVENT_BUS", "sqlite")
os.environ.setdefault("FSTEC_DATA_DIR", str(_SERVICES / "data"))
os.environ.setdefault("FSTEC_OCR_ENABLED", "false")
os.environ.setdefault("FSTEC_LLM_PROVIDER", "heuristic")
os.environ.setdefault("FSTEC_SECURITY_MODE", "mock")

import requests  # noqa: E402

from shared.auth import hash_password  # noqa: E402
from shared.db import SessionLocal, init_db  # noqa: E402
from shared.models import User  # noqa: E402

GATEWAY = os.environ.get("FSTEC_SMOKE_GATEWAY", "http://127.0.0.1:8666")
SMOKE_LOGIN = os.environ.get("FSTEC_SMOKE_LOGIN", "smoke")
SMOKE_PASSWORD = os.environ.get("FSTEC_SMOKE_PASSWORD", "smoke-pass-123")

SAMPLE_TEXT = """Управление ФСТЭК России
Исходящий № 456/1 от 15 марта 2024 г.

Уважаемые коллеги!

По данным ФСТЭК России, хакерской группировкой проводятся целевые атаки с использованием вредоносного программного обеспечения.
Осуществляется рассылка вредоносных сообщений с адресов вида evil[.]com и 203.0.113.10:8080, почта bad@evil.com.

Сообщаем Вам о следующих угрозах:

1. Хакерской группировкой Rare Werewolf осуществляется рассылка фишинговых писем с архивом (архив с наименованием «doc.zip»).
   В случае реализации угрозы возможна установка вредоносного программного обеспечения.
   Необходимо обновить антивирусные базы в течение 3 дней.

2. Хакерской группировкой Cloud Werewolf осуществляется эксплуатация уязвимости BDU:2024-12345 (CVE-2021-44228)
   в программном обеспечении Apache Log4j, уровень опасности по CVSS 9.8 — критический.
   Необходимо произвести обновление до версии 2.17.0 до 01.06.2025.
"""


def fail(msg: str):
    print("FAIL:", msg)
    sys.exit(1)


def make_docx_bytes(text: str = SAMPLE_TEXT) -> bytes:
    from docx import Document as DocxDocument
    buf = io.BytesIO()
    d = DocxDocument()
    for line in text.split("\n"):
        d.add_paragraph(line)
    d.save(buf)
    return buf.getvalue()


def ensure_smoke_user():
    init_db()
    with SessionLocal() as db:
        u = db.query(User).filter(User.username == SMOKE_LOGIN).first()
        if not u:
            db.add(User(username=SMOKE_LOGIN, password_hash=hash_password(SMOKE_PASSWORD),
                       role="admin", full_name="Smoke admin", is_active=True))
            db.commit()
            print(f"[auth] создан dev-пользователь '{SMOKE_LOGIN}' (admin)")


def wait_gateway(timeout_s: float = 45) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = requests.get(f"{GATEWAY}/api/auth/status", timeout=2)
            if r.status_code == 200:
                print("[gateway] up", r.json())
                return
        except requests.ConnectionError:
            pass
        time.sleep(0.5)
    fail(f"gateway {GATEWAY} не поднялся за {timeout_s}с (запустите run_local.ps1)")


def login() -> str:
    r = requests.post(f"{GATEWAY}/api/auth/login",
                      json={"username": SMOKE_LOGIN, "password": SMOKE_PASSWORD}, timeout=5)
    if r.status_code != 200:
        fail(f"login: {r.status_code} {r.text}")
    return r.json()["access_token"]


def wait_workers_subscribed(timeout_s: float = 90) -> None:
    """Sqlite-шина: курсор создаётся при подписке воркера — ждём, пока все подписаны."""
    import sqlite3

    from shared.config import DB_PATH
    topics = {"documents.uploaded", "document.parsed", "document.analyzed", "security.assessed"}
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            conn = sqlite3.connect(str(DB_PATH), timeout=3)
            rows = conn.execute("SELECT DISTINCT topic FROM bus_cursor").fetchall()
            conn.close()
        except sqlite3.Error:
            rows = []
        subscribed = {r[0] for r in rows}
        missing = topics - subscribed
        if not missing:
            print("[workers] все 4 воркера подписаны")
            return
        time.sleep(0.5)
    fail(f"воркеры не подписались за {timeout_s}с: {sorted(missing)}")


def _mime(ext: str) -> str:
    return {
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".odt": "application/vnd.oasis.opendocument.text",
        ".rtf": "application/rtf",
        ".txt": "text/plain",
        ".pdf": "application/pdf",
        ".doc": "application/msword",
    }[ext]


def upload_and_wait(headers, filename: str, content: bytes, mime: str, timeout_s: float = 120) -> dict:
    files = {"files": (filename, content, mime)}
    r = requests.post(f"{GATEWAY}/upload", files=files, headers=headers, timeout=30)
    if r.status_code != 201:
        fail(f"upload {filename}: {r.status_code} {r.text}")
    doc_id = r.json()["id"]
    deadline = time.time() + timeout_s
    data = None
    while time.time() < deadline:
        r = requests.get(f"{GATEWAY}/documents/{doc_id}", headers=headers, timeout=10)
        if r.status_code != 200:
            fail(f"doc get: {r.status_code} {r.text}")
        data = r.json()
        stage, status = data["processing_stage"], data["status"]
        print(f"[poll:{doc_id}] stage={stage!r} status={status!r}")
        if stage == "done" and status == "completed":
            return data
        time.sleep(0.5)
    fail(f"{filename}: документ не завершился за 120с (стадия {data and data.get('processing_stage')})")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all-formats", action="store_true",
                        help="прогнать docx/xlsx/rtf/txt/odt/pdf/doc вместо одиночного docx")
    args = parser.parse_args()

    print(f"gateway={GATEWAY} bus=sqlite data={os.environ['FSTEC_DATA_DIR']}")
    ensure_smoke_user()
    wait_gateway()
    wait_workers_subscribed()
    token = login()
    headers = {"Authorization": f"Bearer {token}"}

    if args.all_formats:
        from tests.formats import BUILDERS
        for ext, builder in BUILDERS.items():
            print(f"--- format {ext}")
            data = upload_and_wait(headers, f"smoke{ext}", builder(), _mime(ext))
            assert data["ioc_count"] >= 1, data
            assert data["vuln_count"] >= 1, data
            assert "CVE-2021-44228" in data["all_text"], data.get("all_text", "")[:200]
            print(f"[format {ext}] ok ioc={data['ioc_count']} vuln={data['vuln_count']}")
        print("PASS: all formats = " + ", ".join(BUILDERS))
        return

    data = upload_and_wait(headers, "letter.docx", make_docx_bytes(),
                           "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    doc_id = data["id"]

    assert data["letter_type"] == "hacker", data["letter_type"]
    assert data["sla"] == "critical", data["sla"]
    assert data["routing"] == "infosec", data["routing"]

    vulns = data["vulnerabilities"]
    if not vulns:
        fail("нет уязвимостей (keep-all должен был сохранить raw)")
    log4j = next((v for v in vulns if "log4j" in (v.get("software") or "").lower()), None)
    if not log4j:
        fail("Log4j не найден в уязвимостях")
    assert log4j["cmdb_match"] is True, log4j
    assert log4j["source"] in ("nvd", "bdu", "manual"), log4j
    assert log4j["target_version"], log4j
    assert log4j["recommendation"], log4j
    print(f"[vuln] Log4j: source={log4j['source']} match={log4j['cmdb_match']} "
          f"current={log4j['current_version']!r} target={log4j['target_version']!r}")

    r = requests.get(f"{GATEWAY}/reports/{doc_id}/download", headers=headers, timeout=10)
    if r.status_code != 200 or not r.content.startswith(b"PK"):
        fail(f"карточка индикаторов: {r.status_code} / не DOCX")
    if not r.headers.get("content-disposition", "").startswith("attachment"):
        fail("content-disposition не attachment")
    print(f"[report] indicator card DOCX, {len(r.content)} bytes")

    r = requests.post(f"{GATEWAY}/reply/generate", params={"doc_id": doc_id}, headers=headers, timeout=30)
    if r.status_code != 200:
        fail(f"reply/generate: {r.status_code} {r.text}")
    if not (r.json().get("text") or "").strip():
        fail("текст ответа пуст")
    print(f"[reply] generated ({len(r.json()['text'])} chars)")

    print("PASS: local E2E (upload -> parsed -> analyzed -> assessed -> completed -> report -> reply)")


if __name__ == "__main__":
    main()