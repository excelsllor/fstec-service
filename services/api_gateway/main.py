"""API Gateway (ТЗ 2.6, 3.1). Внешний контур микросервисной архитектуры.

Эндпоинты ТЗ 2.6: POST /upload, GET /documents, GET /documents/{id},
GET /reports/{id}/download, GET /reports/{id}/download_raw, POST /reply/generate.
Плюс обратная совместимость: /api/letters/... и /api/auth/*.
"""
import base64
import hashlib
import json
import logging
import os
import shutil
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from shared import bus as eventbus
from shared.auth import (
    create_access_token, create_refresh_token, decode_token, ensure_bootstrap, get_current_user, revoke_token, is_token_revoked,
    hash_password, mark_bootstrap_used, needs_setup, require_admin, verify_password,
)
from shared.config import (
    ALLOWED_EXTENSIONS, BOOTSTRAP_PASSWORD, BOOTSTRAP_USERNAME, CORS_ORIGINS,
    DATA_DIR, DISABLE_DOCS, MAX_FILE_SIZE, MAX_FILES_PER_BATCH,
    MIN_PASSWORD_LENGTH, ORG_NAME, REPORT_DIR, UPLOAD_DIR,
)
from shared.db import SessionLocal, get_db, init_db
from shared.events import DocumentsUploaded
from shared.models import (
    Attachment, AuditLog, BootstrapSecret, Document, DocumentTable, Entity, GeneratedResponse, Report,
    IoC, Measure, MeasureCandidate, MeasureTemplate, Report, Summary,
    Threat, ThreatType, User, VulnActionTemplate, Vulnerability,
)

logger = logging.getLogger("fstec.gateway")

# IP клиента текущего запроса (заполняется middleware) — используется аудитом,
# чтобы не передавать Request в каждую ручку.
_client_ip: ContextVar[str] = ContextVar("fstec_client_ip", default="")

# --- Rate limit на /api/auth/login (анти-брутфорс; off для автотестов) ---

_LOGIN_LIMIT = int(os.environ.get("FSTEC_LOGIN_RATE_LIMIT", "10"))
_LOGIN_WINDOW_S = int(os.environ.get("FSTEC_LOGIN_RATE_WINDOW_S", "60"))
_LOGIN_LIMIT_DISABLED = os.environ.get("FSTEC_DISABLE_LOGIN_RATE_LIMIT", "0") == "1"

_login_attempts: dict[str, deque] = {}
_login_lock = threading.Lock()


def _login_allowed(client_ip: str) -> bool:
    if _LOGIN_LIMIT_DISABLED:
        return True
    now = time.monotonic()
    with _login_lock:
        q = _login_attempts.setdefault(client_ip, deque())
        while q and now - q[0] > _LOGIN_WINDOW_S:
            q.popleft()
        if len(q) >= _LOGIN_LIMIT:
            return False
        q.append(now)
        return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as sess:
        ensure_bootstrap(sess)
    yield


app = FastAPI(
    title="FSTEC API Gateway", version="1.0.0",
    docs_url=None if DISABLE_DOCS else "/api/docs",
    redoc_url=None,
    openapi_url=None if DISABLE_DOCS else "/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@app.middleware("http")
async def _add_security_headers(request: Request, call_next):
    # request.client.host учитывает X-Forwarded-For при uvicorn --proxy-headers.
    _client_ip.set(request.client.host if request.client else "")
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@app.exception_handler(OverflowError)
async def _overflow_exception_handler(request: Request, exc: OverflowError):
    # Числовые параметры (id в пути, offset) вне диапазона SQLite INTEGER.
    return JSONResponse(status_code=422, content={"detail": "Некорректное числовое значение параметра"})


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка сервера"})


def _utcnow():
    return datetime.now(timezone.utc)


def _content_disposition(filename: str) -> str:
    """Content-Disposition с ASCII-fallback и RFC 5987 (*=UTF-8'') для кириллицы."""
    from urllib.parse import quote
    try:
        filename.encode("latin-1")
        return f"attachment; filename={filename}"
    except UnicodeEncodeError:
        safe = filename.encode("ascii", "replace").decode("ascii") or "download"
        return f"attachment; filename={safe}; filename*=UTF-8''{quote(filename)}"


def _audit(db: Session, user: User | None, action: str, object_type: str = "",
           object_id: int | None = None, filename: str = "", document_id: int | None = None,
           request: Request | None = None):
    rec = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "",
        action=action,
        object_type=object_type,
        object_id=object_id,
        filename=filename,
        document_id=document_id,
        ip_address=(request.client.host if request and request.client else _client_ip.get()),
    )
    db.add(rec)
    # Аудит должен сохраняться всегда: часть ручек вызывает _audit уже после
    # db.commit(), поэтому коммитим запись здесь (иначе она теряется при закрытии сессии).
    db.commit()


def _owned_document(db: Session, user: User, doc_id: int,
                    detail: str = "Документ не найден") -> Document:
    """Возвращает документ, только если он принадлежит пользователю (или он admin).

    Для чужих документов отдаём 404, чтобы не раскрывать их существование.
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if doc is None or (user.role != "admin" and doc.created_by != user.id):
        raise HTTPException(status_code=404, detail=detail)
    return doc


def _scoped_documents(db: Session, user: User):
    """Базовый запрос документов с учётом объектной авторизации.

    Удалённые письма (status='deleted') не попадают в списки и статистику.
    """
    query = db.query(Document).filter(Document.status != "deleted")
    if user.role != "admin":
        query = query.filter(Document.created_by == user.id)
    return query


# ---------------- Auth ----------------

@app.post("/api/auth/login")
def login(body: dict, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not _login_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много попыток входа, повторите позже")
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        _audit(db, None, "login_failed", "user", user.id if user else None, filename=username, request=request)
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    if not user.is_active:
        raise HTTPException(status_code=401, detail="Учётная запись отключена")
    if user.username == BOOTSTRAP_USERNAME:
        mark_bootstrap_used(db)
    _audit(db, user, "login", "user", user.id, request=request)
    db.commit()
    claims = {"sub": user.username, "role": user.role}
    token = create_access_token(claims)
    refresh = create_refresh_token(claims)
    return {"access_token": token, "refresh_token": refresh, "token_type": "bearer",
            "role": user.role, "username": user.username}


@app.get("/api/auth/status")
def auth_status(db: Session = Depends(get_db)):
    """Статус первичной инициализации. Пока bootstrap-админ не вошёл ни разу,
    экран входа показывает его одноразовые учётные данные (ТЗ: доступ один раз)."""
    setup = needs_setup(db)
    payload = {"needs_setup": setup}
    if setup:
        payload.update({"bootstrap_username": BOOTSTRAP_USERNAME,
                        "bootstrap_source": "env" if BOOTSTRAP_PASSWORD else "file"})
    return payload


@app.post("/api/auth/logout")
def logout(request: Request, body: dict | None = None,
           db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    auth = request.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        revoke_token(auth.split(" ", 1)[1])
    refresh = (body or {}).get("refresh_token")
    if refresh:
        revoke_token(str(refresh))
    _audit(db, user, "logout", "user", user.id, request=request)
    return {"ok": True}


@app.post("/api/auth/refresh")
def refresh_token(body: dict, db: Session = Depends(get_db)):
    refresh = str((body or {}).get("refresh_token") or "")
    if not refresh:
        raise HTTPException(status_code=401, detail="??? refresh token")
    try:
        payload = decode_token(refresh)
    except Exception:
        raise HTTPException(status_code=401, detail="???????????????? refresh token")
    if payload.get("type") != "refresh" or payload.get("sub") is None or is_token_revoked(refresh):
        raise HTTPException(status_code=401, detail="???????????????? refresh token")
    user = db.query(User).filter(User.username == payload["sub"]).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="???????????? ?? ??????")
    claims = {"sub": user.username, "role": user.role}
    token = create_access_token(claims)
    new_refresh = create_refresh_token(claims)
    revoke_token(refresh)
    _audit(db, user, "refresh", "user", user.id)
    return {"access_token": token, "refresh_token": new_refresh, "token_type": "bearer",
            "role": user.role, "username": user.username}


@app.get("/api/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role,
            "full_name": user.full_name, "is_active": user.is_active,
            "created_at": user.created_at}


# ---------------- Users (admin, ТЗ 5: управление доступом) ----------------

def _serialize_user(u: User) -> dict:
    return {"id": u.id, "username": u.username, "role": u.role,
            "full_name": u.full_name, "is_active": u.is_active,
            "created_at": u.created_at}


def _other_active_admins(db: Session, exclude_id: int) -> int:
    return db.query(User).filter(
        User.role == "admin", User.is_active.is_(True), User.id != exclude_id).count()


def _validate_new_password(password: str) -> str:
    pw = (password or "").strip()
    if len(pw) < MIN_PASSWORD_LENGTH:
        raise HTTPException(status_code=400,
                            detail=f"Пароль должен быть не короче {MIN_PASSWORD_LENGTH} символов")
    return pw


@app.get("/api/users")
def users_list(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_serialize_user(u) for u in db.query(User).order_by(User.id).all()]


@app.post("/api/users", status_code=201)
def users_create(body: dict, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    username = (body.get("username") or "").strip()
    role = (body.get("role") or "user").strip()
    full_name = (body.get("full_name") or "").strip()
    if not username or len(username) > 100:
        raise HTTPException(status_code=400, detail="Логин обязателен (до 100 символов)")
    if role not in ("admin", "user"):
        raise HTTPException(status_code=400, detail="Роль должна быть admin или user")
    password = _validate_new_password(body.get("password") or "")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=409, detail="Пользователь с таким логином уже существует")
    rec = User(username=username, password_hash=hash_password(password),
               role=role, full_name=full_name[:200], is_active=True)
    db.add(rec)
    db.flush()
    _audit(db, user, "create_user", "user", rec.id, request=request)
    db.commit()
    return _serialize_user(rec)


@app.put("/api/users/{user_id}")
def users_update(user_id: int, body: dict, request: Request,
                 db: Session = Depends(get_db), user: User = Depends(require_admin)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if body.get("full_name") is not None:
        target.full_name = str(body["full_name"])[:200]
    if body.get("role") is not None:
        role = str(body["role"])
        if role not in ("admin", "user"):
            raise HTTPException(status_code=400, detail="Роль должна быть admin или user")
        if (target.role == "admin" and role != "admin"
                and target.is_active and _other_active_admins(db, target.id) == 0):
            raise HTTPException(status_code=400, detail="Нельзя понизить последнего администратора")
        target.role = role
    if body.get("is_active") is not None:
        active = bool(body["is_active"])
        if (target.role == "admin" and not active
                and _other_active_admins(db, target.id) == 0):
            raise HTTPException(status_code=400, detail="Нельзя отключить последнего администратора")
        if not active and target.id == user.id:
            raise HTTPException(status_code=400, detail="Нельзя отключить собственную учётную запись")
        target.is_active = active
    if body.get("password"):
        target.password_hash = hash_password(_validate_new_password(str(body["password"])))
    _audit(db, user, "update_user", "user", target.id, request=request)
    db.commit()
    return _serialize_user(target)


@app.delete("/api/users/{user_id}")
def users_delete(user_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(require_admin)):
    target = db.query(User).filter(User.id == user_id).first()
    if not target:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="Нельзя удалить собственную учётную запись")
    if (target.role == "admin" and target.is_active
            and _other_active_admins(db, target.id) == 0):
        raise HTTPException(status_code=400, detail="Нельзя удалить последнего администратора")
    owned = db.query(Document).filter(Document.created_by == target.id).count()
    if owned:
        target.is_active = False
        _audit(db, user, "deactivate_user", "user", target.id, request=request)
        db.commit()
        return {"id": target.id, "deleted": False, "deactivated": True,
                "detail": f"У пользователя {owned} писем — учётная запись отключена"}
    _audit(db, user, "delete_user", "user", target.id, request=request)
    db.delete(target)
    db.commit()
    return {"id": user_id, "deleted": True, "deactivated": False}


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------------- Upload (ТЗ 2.6 POST /upload) ----------------

_MAGIC = {
    ".pdf": (b"%PDF", 4),
    ".docx": (b"PK\x03\x04", 4),
    ".xlsx": (b"PK\x03\x04", 4),
    ".odt": (b"PK\x03\x04", 4),
    ".doc": (b"\xd0\xcf\x11\xe0", 4),
    ".rtf": (b"{\\rtf", 5),
}


def _validate_file(uf: UploadFile):
    ext = Path(uf.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Недопустимый формат: {ext or '(нет расширения)'}")
    uf.file.seek(0, os.SEEK_END)
    size = uf.file.tell()
    uf.file.seek(0)
    if size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"Файл {uf.filename} больше 20 МБ")
    magic, n = _MAGIC.get(ext, (None, 0))
    if magic:
        head = uf.file.read(n)
        uf.file.seek(0)
        if ext == ".rtf":
            head = head.lstrip(b"\x00\x09\x0a\x0d\x20")
        if not head.startswith(magic):
            raise HTTPException(status_code=415, detail=f"Файл {uf.filename} не соответствует формату {ext}")
    uf.file.seek(0)
    return size


@app.post("/upload", status_code=201)
async def upload(
    request: Request,
    files: Optional[list[UploadFile]] = File(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not files:
        raise HTTPException(status_code=400, detail="Нет файлов")
    if len(files) > MAX_FILES_PER_BATCH:
        raise HTTPException(status_code=413, detail=f"Допускается до {MAX_FILES_PER_BATCH} файлов одновременно")

    sizes = []
    for uf in files:
        sizes.append(_validate_file(uf))

    main_name = Path(files[0].filename).name
    doc = Document(
        letter_type="other", status="uploaded", processing_stage="uploaded",
        source_filename=main_name,
        size=sum(sizes), mime=Path(main_name).suffix,
        created_by=user.id,
    )
    db.add(doc)
    db.flush()

    doc_dir = UPLOAD_DIR / f"doc_{doc.id}"
    doc_dir.mkdir(parents=True, exist_ok=True)
    doc.file_path = str(doc_dir)

    att_metas = []
    for idx, uf in enumerate(files):
        name = Path(uf.filename).name
        dest = doc_dir / f"{idx}_{name}"
        with open(dest, "wb") as f:
            shutil.copyfileobj(uf.file, f)
        db.add(Attachment(
            document_id=doc.id, filename=name, file_path=str(dest),
            file_type=Path(name).suffix.lower(), parse_status="pending", is_main=(idx == 0),
        ))
        att_metas.append({"filename": name, "path": str(dest), "size": sizes[idx]})

    digest = hashlib.sha256()
    for meta in att_metas:
        with open(meta["path"], "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                digest.update(chunk)
    doc.content_hash = digest.hexdigest()
    db.flush()

    duplicate = (db.query(Document)
                 .filter(Document.content_hash == doc.content_hash,
                         Document.id != doc.id,
                         Document.status == "completed",
                         Document.processing_stage == "done")
                 .order_by(Document.id.desc()).first())
    if duplicate and (user.role == "admin" or duplicate.created_by == user.id):
        db.delete(doc)
        db.commit()
        shutil.rmtree(doc_dir, ignore_errors=True)
        _audit(db, user, "upload_duplicate", "document", duplicate.id,
               files[0].filename, duplicate.id, request=request)
        return {"id": duplicate.id, "status": duplicate.status,
                "filename": files[0].filename, "duplicate": True}

    _audit(db, user, "upload", "document", doc.id, files[0].filename, doc.id, request=request)
    db.commit()

    await eventbus.publish("documents.uploaded", str(doc.id), DocumentsUploaded(
        document_id=doc.id,
        user_id=user.id,
        main_file=att_metas[0],
        attachments=att_metas[1:],
    ).model_dump(mode="json"))

    return {"id": doc.id, "status": "uploaded", "filename": files[0].filename}


# ---------------- Documents (ТЗ 2.6) ----------------

@app.get("/documents")
def list_documents(
    skip: int = Query(0, ge=0, le=1_000_000), limit: int = Query(50, ge=1, le=200),
    letter_type: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _scoped_documents(db, user)
    if letter_type:
        query = query.filter(Document.letter_type == letter_type)
    if status:
        query = query.filter(Document.status == status)
    docs = query.order_by(Document.created_at.desc()).offset(skip).limit(limit).all()
    return [{
        "id": d.id, "letter_number": d.letter_number, "letter_date": d.letter_date,
        "letter_type": d.letter_type, "status": d.status, "sla": d.sla, "routing": d.routing,
        "source_filename": d.source_filename, "processing_stage": d.processing_stage,
        "created_at": d.created_at,
    } for d in docs]


def _document_brief(doc: Document):
    return {
        "id": doc.id,
        "letter_number": doc.letter_number,
        "letter_date": doc.letter_date,
        "letter_type": doc.letter_type,
        "status": doc.status,
        "sla": doc.sla,
        "routing": doc.routing,
        "source_filename": doc.source_filename,
        "processing_stage": doc.processing_stage,
        "created_at": doc.created_at,
        "progress_percent": _document_progress(doc),
        "eta_seconds": _document_eta(doc),
    }


def _document_progress(doc: Document) -> int:
    return {
        "uploaded": 10, "parsed": 35, "analyzed": 60,
        "assessed": 80, "done": 100, "completed": 100,
        "failed": 100, "error": 100,
    }.get((doc.processing_stage or "").lower(), 20 if doc.status == "uploaded" else 50)


def _document_eta(doc: Document) -> int | None:
    stage = (doc.processing_stage or "").lower()
    if stage in ("done", "completed", "failed", "error"):
        return 0
    return {"uploaded": 60, "parsed": 30, "analyzed": 12, "assessed": 5}.get(stage, 60)


def _report_meta(db: Session, doc_id: int) -> dict:
    report = (db.query(Report).filter(Report.document_id == doc_id)
              .order_by(Report.generated_at.desc()).first())
    if not report:
        return {}
    return {"filename": report.filename,
            "generated_at": report.generated_at.isoformat() if report.generated_at else ""}


def _serialize_document(db: Session, doc: Document) -> dict:
    tables = []
    for t in db.query(DocumentTable).filter(DocumentTable.document_id == doc.id).order_by(DocumentTable.table_index).all():
        try:
            rows = json.loads(t.rows_json or "[]")
        except Exception:
            rows = []
        tables.append({"index": t.table_index, "rows": rows})

    attachments = [{
        "id": a.id, "filename": a.filename, "file_type": a.file_type,
        "parse_status": a.parse_status, "parse_errors": a.parse_errors,
        "parsed_text": a.parsed_text, "is_main": a.is_main,
    } for a in doc.attachments]

    threats = [{
        "id": t.id, "number": t.number, "group_name": t.group_name,
        "threat_type": t.threat_type, "theme": t.theme,
        "archive_name": t.archive_name, "exe_name": t.exe_name,
        "malware_type": t.malware_type, "description": t.description,
        "measures": t.measures,
    } for t in doc.threats]

    iocs = [{
        "id": i.id, "ioc_type": i.ioc_type, "value": i.value,
        "context": i.context, "llm_validated": i.llm_validated, "source": i.source,
    } for i in doc.iocs]

    vulnerabilities = [{
        "id": v.id, "bdu_id": v.bdu_id, "cve_id": v.cve_id,
        "description": v.description, "software": v.software, "severity": v.severity,
        "cvss_score": v.cvss_score, "cpe": v.cpe, "affected_range": v.affected_range,
        "fixed_version": v.fixed_version, "patch_url": v.patch_url,
        "cmdb_match": v.cmdb_match, "current_version": v.current_version,
        "target_version": v.target_version, "source": v.source,
        "cmdb_error": v.cmdb_error or "", "recommendation": v.recommendation,
        "is_applicable": v.is_applicable, "applicability_notes": v.applicability_notes,
        "action_type": v.action_type, "action_details": v.action_details,
        "response_point": v.response_point,
    } for v in doc.vulnerabilities]

    entities = [{
        "id": e.id, "entity_type": e.entity_type, "value": e.value, "context": e.context,
    } for e in db.query(Entity).filter(Entity.document_id == doc.id).all()]

    summaries = [{"id": s.id, "summary": s.summary, "confidence": s.confidence}
                 for s in db.query(Summary).filter(Summary.document_id == doc.id).all()]

    resp = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id)
            .order_by(GeneratedResponse.id.desc()).first())

    data = _document_brief(doc)
    data.update({
        "subject": doc.subject,
        "original_text": doc.original_text,
        "all_text": doc.all_text,
        "parse_errors": doc.parse_errors,
        "ocr_used": doc.ocr_used,
        "updated_at": doc.updated_at,
        "attachments": attachments,
        "tables": tables,
        "threats": threats,
        "iocs": iocs,
        "vulnerabilities": vulnerabilities,
        "entities": entities,
        "summaries": summaries,
        "ioc_count": len(iocs),
        "vuln_count": len(vulnerabilities),
        "threat_count": len(threats),
        "response": {"text": resp.content or "", "exists": resp is not None, "id": resp.id} if resp
        else {"text": "", "exists": False},
        "report": _report_meta(db, doc.id),
    })
    return data


@app.get("/documents/{doc_id}")
def get_document(doc_id: int, request: Request, view: bool = Query(False),
                 db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, doc_id)
    if view:
        _audit(db, user, "view_document", "document", doc_id, doc.source_filename, doc_id, request=request)
    return _serialize_document(db, doc)


# ---------------- Reports (ТЗ 2.6) ----------------

@app.get("/reports/{doc_id}/download")
def download_report(doc_id: int, request: Request, db: Session = Depends(get_db),
                    user: User = Depends(get_current_user)):
    _owned_document(db, user, doc_id)
    report = (db.query(Report).filter(Report.document_id == doc_id)
              .order_by(Report.generated_at.desc()).first())
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт ещё не сформирован")
    if not report.file_path or not Path(report.file_path).exists():
        raise HTTPException(status_code=404, detail="Report file not found")
    _audit(db, user, "download_report", "document", doc_id, report.filename, doc_id, request=request)
    return FileResponse(report.file_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        filename=report.filename)


@app.get("/reports/{doc_id}/download_raw")
def download_raw(doc_id: int, request: Request, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, doc_id)
    main = (db.query(Attachment).filter(Attachment.document_id == doc_id, Attachment.is_main == True).first())
    path = main.file_path if main else (doc.file_path and os.path.join(doc.file_path, doc.source_filename))
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="Исходный файл не найден")
    _audit(db, user, "download_source", "document", doc_id, doc.source_filename, doc_id, request=request)
    return FileResponse(path, filename=doc.source_filename)


@app.post("/reports/{doc_id}/regenerate")
def regenerate_report(doc_id: int, request: Request, db: Session = Depends(get_db),
                      user: User = Depends(get_current_user)):
    """Пересобрать карточку индикаторов после ручных правок (ТЗ 2.5.1)."""
    doc = _owned_document(db, user, doc_id)
    iocs = db.query(IoC).filter(IoC.document_id == doc_id).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()
    from shared.generator.indicator_card import build_indicator_card, report_filename
    card = build_indicator_card(
        org_name=ORG_NAME,
        source_filename=doc.source_filename,
        document_id=doc.id,
        ips=[i.value for i in iocs if i.ioc_type in ("ip", "ip_cidr")],
        ipv6=[i.value for i in iocs if i.ioc_type == "ipv6"],
        domains=[i.value for i in iocs if i.ioc_type == "domain"],
        emails=[i.value for i in iocs if i.ioc_type == "email"],
        vulnerabilities=[{
            "cve_id": v.cve_id, "bdu_id": v.bdu_id, "description": v.description,
            "software": v.software, "severity": v.severity, "cvss_score": v.cvss_score,
            "current_version": v.current_version, "target_version": v.target_version,
            "fixed_version": v.fixed_version, "cmdb_match": v.cmdb_match,
        } for v in vulns],
        sla=doc.sla,
    )
    fname = report_filename(doc.source_filename)
    report_dir = REPORT_DIR / f"doc_{doc.id}"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / fname
    report_path.write_bytes(card)
    db.add(Report(document_id=doc.id, report_type="indicator_card",
                  filename=fname, file_path=str(report_path)))
    _audit(db, user, "regenerate_report", "document", doc_id, fname, doc_id, request=request)
    db.commit()
    return {"filename": fname, "document_id": doc_id}


@app.post("/reply/generate")
def reply_generate(doc_id: int, request: Request, body: dict | None = None,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """Принудительная генерация проекта ответа (ТЗ 2.6 /reply/generate)."""
    from shared.generator.templated_reply import generate_reply, persist_candidates
    doc = _owned_document(db, user, doc_id)
    threat_rows = (db.query(Threat).filter(Threat.document_id == doc_id)
                   .order_by(Threat.number).all())
    blocks = [{
        "id": t.id, "number": t.number, "threat_type": t.threat_type, "theme": t.theme,
        "group_name": t.group_name, "archive_name": t.archive_name, "exe_name": t.exe_name,
        "malware_type": t.malware_type, "description": t.description,
        "explicit_measures": [m.strip() for m in (t.measures or "").split("\n") if m.strip()],
    } for t in threat_rows]
    vulns = [{"cve_id": v.cve_id, "bdu_id": v.bdu_id, "description": v.description or "",
              "software": v.software, "severity": v.severity, "cvss_score": v.cvss_score,
              "cvss_version": v.cvss_version or "", "current_version": v.current_version,
              "target_version": v.target_version, "fixed_version": v.fixed_version,
              "cmdb_match": v.cmdb_match, "recommendation": v.recommendation}
             for v in db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()]
    iocs = db.query(IoC).filter(IoC.document_id == doc_id).all()
    addr_count = len({i.value.split(":")[0] for i in iocs if i.ioc_type in ("ip", "domain")})

    rep = generate_reply(db=db, doc_id=doc.id, letter_type=doc.letter_type, blocks=blocks,
                         addr_count=addr_count, active_vulns=vulns)
    if rep["candidates"]:
        for i, c in enumerate(rep["candidates"]):
            rep["candidates"][i]["threat_id"] = (blocks[i]["id"] if i < len(blocks) else None)
        persist_candidates(db, doc.id, rep["candidates"])

    resp = GeneratedResponse(document_id=doc_id, content=rep["text"],
                             edited_content=base64.b64encode(rep["docx"]).decode("ascii"),
                             plan_json=rep["plan_json"], created_by=user.id)
    db.add(resp)
    _audit(db, user, "generate_reply", "document", doc_id, doc.source_filename, doc_id, request=request)
    db.commit()
    return {"id": resp.id, "document_id": doc_id, "status": "generated", "text": rep["text"],
            "llm_used": rep["llm_used"], "new_measures": len(rep["candidates"])}


# ---------------- Admin: библиотека мер и очередь кандидатов (LLM) ----------------

@app.get("/admin/measures")
def admin_measures(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.query(Measure).order_by(Measure.id).all()
    return [{"id": m.id, "text": m.text, "threat_type": m.threat_type, "tags": m.tags,
             "addr_inflection": m.addr_inflection, "source": m.source} for m in rows]


@app.post("/admin/measures")
def admin_measures_add(body: dict, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text обязателен")
    dup = db.query(Measure).filter(Measure.text == text).first()
    if dup:
        return {"id": dup.id, "status": "exists"}
    m = Measure(text=text, threat_type=body.get("threat_type", ""),
                tags=body.get("tags", ""), addr_inflection=bool(body.get("addr_inflection", False)),
                source="admin")
    db.add(m)
    db.commit()
    _audit(db, user, "measure_add", "measure", m.id)
    return {"id": m.id, "status": "added"}


@app.delete("/admin/measures/{measure_id}")
def admin_measures_delete(measure_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    m = db.query(Measure).filter(Measure.id == measure_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Мера не найдена")
    db.delete(m)
    db.commit()
    _audit(db, user, "measure_delete", "measure", measure_id)
    return {"status": "deleted"}


@app.get("/admin/measures/candidates")
def admin_candidates(status: str | None = "pending", db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    q = db.query(MeasureCandidate)
    if status:
        q = q.filter(MeasureCandidate.status == status)
    rows = q.order_by(MeasureCandidate.id.desc()).all()
    out = []
    for c in rows:
        doc = db.query(Document).filter(Document.id == c.document_id).first()
        threat = (db.query(Threat).filter(Threat.id == c.threat_id).first()
                  if c.threat_id else None)
        out.append({
            "id": c.id, "text": c.text, "note": c.note, "status": c.status,
            "document_id": c.document_id,
            "letter_number": doc.letter_number if doc else "",
            "letter_date": doc.letter_date if doc else "",
            "threat_theme": (threat.theme or threat.description or "") if threat else "",
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "reviewed_at": c.reviewed_at.isoformat() if c.reviewed_at else None,
        })
    return out


@app.post("/admin/measures/candidates/{candidate_id}/accept")
def admin_candidate_accept(candidate_id: int, db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == candidate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Кандидат не найден")
    if c.status == "approved":
        return {"id": c.id, "status": "already_approved"}
    dup = db.query(Measure).filter(Measure.text == c.text).first()
    if not dup:
        dup = Measure(text=c.text, threat_type="", tags="", addr_inflection=False, source="llm")
        db.add(dup)
    c.status = "approved"
    c.reviewed_by = user.id
    c.reviewed_at = _utcnow()
    db.commit()
    _audit(db, user, "candidate_accept", "measure_candidate", candidate_id)
    return {"id": c.id, "status": "approved", "measure_id": dup.id}


@app.post("/admin/measures/candidates/{candidate_id}/reject")
def admin_candidate_reject(candidate_id: int, db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == candidate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Кандидат не найден")
    c.status = "rejected"
    c.reviewed_by = user.id
    c.reviewed_at = _utcnow()
    db.commit()
    _audit(db, user, "candidate_reject", "measure_candidate", candidate_id)
    return {"id": c.id, "status": "rejected"}


# ---------------- Legacy compat: /api/letters ----------------
# (обратная совместимость для существующего фронтенда до его перехода на ТЗ 2.6)

@app.get("/api/audit")
def list_audit(skip: int = 0, limit: int = 200, action: str = "", document_id: int | None = None,
               db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="???????????? ????")
    q = db.query(AuditLog)
    if action:
        q = q.filter(AuditLog.action == action)
    if document_id is not None:
        q = q.filter(AuditLog.document_id == document_id)
    total = q.count()
    rows = q.order_by(AuditLog.created_at.desc()).offset(max(0, skip)).limit(min(500, max(1, limit))).all()
    return {"total": total, "items": [
        {"id": r.id, "user_id": r.user_id, "username": r.username, "action": r.action,
         "object_type": r.object_type, "object_id": r.object_id, "filename": r.filename,
         "document_id": r.document_id, "ip_address": r.ip_address,
         "created_at": r.created_at.isoformat() if r.created_at else ""}
        for r in rows
    ]}


@app.get("/api/letters")
def legacy_list(skip: int = Query(0, ge=0, le=1_000_000), limit: int = Query(50, ge=1, le=200),
                letter_type: str | None = None, status: str | None = None,
                mine: bool = Query(True), db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    query = _scoped_documents(db, user)
    if mine:
        query = query.filter(Document.created_by == user.id)
    if letter_type:
        query = query.filter(Document.letter_type == letter_type)
    if status:
        query = query.filter(Document.status == status)
    docs = query.order_by(Document.created_at.desc()).offset(skip).limit(limit).all()
    return [{"id": d.id, "letter_number": d.letter_number, "letter_date": d.letter_date,
             "letter_type": d.letter_type, "status": d.status, "created_at": d.created_at,
             "threat_count": db.query(Threat).filter(Threat.document_id == d.id).count(),
             "ioc_count": db.query(IoC).filter(IoC.document_id == d.id).count(),
             "vuln_count": db.query(Vulnerability).filter(Vulnerability.document_id == d.id).count()}
            for d in docs]


@app.get("/api/letters/stats")
def legacy_stats(mine: bool = Query(True), db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    scope = _scoped_documents(db, user)
    if mine:
        scope = scope.filter(Document.created_by == user.id)
    doc_ids = [d.id for d in scope.with_entities(Document.id).all()]

    def _count(model) -> int:
        if not doc_ids:
            return 0
        return db.query(model).filter(model.document_id.in_(doc_ids)).count()

    return {
        "total_letters": len(doc_ids),
        "hacker_letters": scope.filter(Document.letter_type == "hacker").count(),
        "vulnerability_letters": scope.filter(Document.letter_type == "vulnerability").count(),
        "other_letters": scope.filter(Document.letter_type == "other").count(),
        "total_threats": _count(Threat),
        "total_iocs": _count(IoC),
        "total_vulns": _count(Vulnerability),
    }


@app.get("/api/letters/{letter_id}")
def legacy_detail(letter_id: int, request: Request, view: bool = Query(False),
                  db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    if view:
        _audit(db, user, "view_document", "document", doc.id, doc.source_filename, doc.id, request=request)
    return _serialize_document(db, doc)


@app.delete("/api/letters/{letter_id}")
def legacy_delete(letter_id: int, request: Request, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """Мягкое удаление письма: скрывается из списков/статистики, данные и файлы
    сохраняются для аудита. Отозвать нельзя через API (только администратором БД)."""
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    doc.status = "deleted"
    doc.processing_stage = "deleted"
    _audit(db, user, "delete_letter", "document", doc.id, document_id=doc.id, request=request)
    db.commit()
    return {"id": doc.id, "status": "deleted"}


@app.get("/api/letters/{letter_id}/response/text")
def legacy_response_text(letter_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    return {"text": (resp.content or "") if resp else "", "exists": resp is not None}


@app.put("/api/letters/{letter_id}/response")
def legacy_response_update(letter_id: int, body: dict, request: Request,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    text = (body.get("content") or "").strip()
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    if not resp:
        resp = GeneratedResponse(document_id=letter_id, content=text, created_by=user.id)
        db.add(resp)
    else:
        resp.content = text
        resp.updated_at = _utcnow()
    from shared.generator.response_generator import render_reply_docx
    resp.edited_content = base64.b64encode(render_reply_docx(text)).decode("ascii")
    _audit(db, user, "update_response", "document", letter_id, request=request)
    db.commit()
    return {"id": resp.id, "text": text}


@app.get("/api/letters/{letter_id}/response/preview")
def legacy_response_preview(letter_id: int, db: Session = Depends(get_db),
                            user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    from shared.generator.reply_preview import build_preview
    threats = db.query(Threat).filter(Threat.document_id == doc.id).order_by(Threat.number).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc.id).all()
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    preview = build_preview(db=db, document=doc, threats=threats,
                            vulnerabilities=vulns, iocs=iocs)
    resp = (db.query(GeneratedResponse)
            .filter(GeneratedResponse.document_id == doc.id)
            .order_by(GeneratedResponse.id.desc()).first())
    if resp:
        preview["text"] = resp.content or ""
    preview["response_exists"] = resp is not None
    return preview


@app.put("/api/letters/{letter_id}/response/measures/{threat_id}")
def legacy_measures_update(letter_id: int, threat_id: int, body: dict, request: Request,
                           db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    measures = body.get("measures") or []
    threat = db.query(Threat).filter(Threat.id == threat_id, Threat.document_id == letter_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Угроза не найдена")
    threat.measures = "\n".join(measures)
    _audit(db, user, "update_measures", "threat", threat_id, document_id=letter_id, request=request)
    db.commit()
    texts = [m.strip() for m in measures if m.strip()]
    return {"measures": measures, "text": "\n".join(f"  {m}" for m in texts)}


def _update_vulnerability(db: Session, user: User, doc_id: int, vuln_id: int,
                          body: dict, request: Request | None = None) -> dict:
    doc = _owned_document(db, user, doc_id, detail="Уязвимость не найдена")
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id, Vulnerability.document_id == doc_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")
    if "is_applicable" in body and body["is_applicable"] is not None:
        vuln.is_applicable = bool(body["is_applicable"])
    for f in ("applicability_notes", "action_type", "action_details", "response_point", "software",
              "current_version", "target_version", "fixed_version", "bdu_id", "cve_id",
              "description", "severity"):
        if f in body and body[f] is not None:
            setattr(vuln, f, body[f])
    if "severity" in body and body["severity"] not in (None, "") and body["severity"] not in {"critical", "high", "medium", "low", "unknown"}:
        raise HTTPException(status_code=400, detail="???????????? severity")
    if "cvss_score" in body:
        try:
            score = float(str(body["cvss_score"]).replace(",", ".")) if body["cvss_score"] not in (None, "") else None
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="???????????? CVSS score")
        if score is not None and not (0 <= score <= 10):
            raise HTTPException(status_code=400, detail="CVSS score ?????? ???? ?? 0 ?? 10")
        vuln.cvss_score = score
    db.commit()
    _audit(db, user, "update_vulnerability", "vulnerability", vuln_id,
           document_id=doc_id, request=request)
    return _serialize_document(db, doc)



@app.post("/api/letters/{letter_id}/vulnerabilities/{vuln_id}/autofill")
def autofill_vulnerability(letter_id: int, vuln_id: int, request: Request,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Letter not found")
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id, Vulnerability.document_id == doc.id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    software = " ".join((vuln.software or "").split())
    target = (vuln.target_version or "").strip()
    fixed = (vuln.fixed_version or "").strip()
    version = target or fixed

    if software:
        try:
            import asyncio
            from security_service.assessment import _match_cmdb
            from security_service.cmdb import get_cmdb
            from security_service.http_pool import close_clients

            try:
                candidates = asyncio.run(get_cmdb().find_many(software))
            finally:
                try:
                    asyncio.run(close_clients())
                except Exception:
                    pass
            installed = [c for c in candidates if c.installed]
            item, matched = _match_cmdb(None, installed, software, fixed_hint=fixed)
            vuln.cmdb_match = matched
            vuln.cmdb_error = ""
            vuln.current_version = (item.version if item else
                                    (installed[0].version if installed else ""))
            vuln.is_applicable = bool(installed)
            if installed:
                vuln.applicability_notes = (
                    f"ПО «{installed[0].name}» {vuln.current_version} найдено в GLPI (список ПО); "
                    f"{installed[0].assets} запись в списке."
                )
            else:
                vuln.applicability_notes = f"ПО «{software}» не найдено в установленном ПО GLPI."
            db.commit()
        except Exception as exc:  # noqa: BLE001 — CMDB недоступна (ТЗ 4.2)
            logger.warning("autofill cmdb lookup failed for %r: %s", software, exc)
            vuln.cmdb_error = f"cmdb:{software}:{str(exc)[:300]}"
            vuln.is_applicable = None
            db.commit()

    current = (vuln.current_version or "").strip()

    if not software:
        applicability = "unknown"
        action_type = ""
    elif vuln.cmdb_match:
        applicability = "true"
        action_type = "update" if version else "compensate"
    elif (vuln.cmdb_error or "").strip():
        applicability = "unknown"
        action_type = ""
    elif vuln.is_applicable is True:
        applicability = "true"
        action_type = "skip"
    else:
        applicability = "false"
        action_type = "skip"

    templates = {t.action_type: t for t in db.query(VulnActionTemplate).all()}
    template = templates.get(action_type)
    details = (template.content or "") if template else ""
    for key, value in (
        ("{{software}}", software), ("{software}", software),
        ("{{current_version}}", current), ("{current_version}", current),
        ("{{target_version}}", version), ("{target_version}", version),
        ("{{fixed_version}}", version), ("{fixed_version}", version),
    ):
        details = details.replace(key, value)
    if action_type == "update" and version and version not in details:
        details = details.rstrip() + f" Обновить до версии: {version}."

    if applicability == "true" and action_type == "update":
        current_part = f" {current}" if current else ""
        notes = f"ПО «{software}»{current_part} обнаружено в GLPI; требуется обновление."
    elif applicability == "false":
        notes = (f"Использование ПО «{software}» в GLPI не найдено; "
                 "обновление не требуется, рекомендуется периодическая проверка.")
    elif applicability == "true":
        notes = (f"ПО «{software}» {current} установлено в GLPI, но уязвимая версия "
                 "не обнаружена; обновление не требуется.")
    elif not software:
        notes = "ПО не указано; автоматический подбор невозможен."
    else:
        err = (vuln.cmdb_error or "").strip()[:300]
        suffix = f": {err}" if err else ""
        notes = f"Не удалось проверить ПО «{software}» в GLPI{suffix}. Требуется ручная проверка."

    vuln.action_type = action_type
    vuln.action_details = details[:1500]
    db.commit()

    result = {
        "action_type": action_type,
        "applicability": applicability,
        "current_version": current,
        "action_details": details[:1500],
        "applicability_notes": notes[:1500],
        "source": "cmdb+library" if template else "cmdb",
        "model": "",
        "llm_used": False,
    }
    _audit(db, user, "autofill_vulnerability", "vulnerability", vuln_id,
           document_id=doc.id, request=request)
    return result


@app.put("/api/letters/{letter_id}/vulnerabilities/{vuln_id}")
def legacy_vuln_update(letter_id: int, vuln_id: int, body: dict, request: Request,
                       db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _update_vulnerability(db, user, letter_id, vuln_id, body, request=request)


@app.post("/api/letters/{letter_id}/iocs")
def ioc_create(letter_id: int, body: dict, request: Request, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    value = str(body.get("value") or "").strip()
    ioc_type = str(body.get("ioc_type") or "").strip().lower()
    if not value or ioc_type not in {"ip", "ipv6", "ip_cidr", "domain", "email", "hash", "bdu", "cve", "url"}:
        raise HTTPException(status_code=400, detail="Некорректный тип или значение IoC")
    db.add(IoC(document_id=doc.id, ioc_type=ioc_type, value=value, source="manual"))
    _audit(db, user, "ioc_create", "document", doc.id, value, doc.id, request=request)
    db.commit()
    return _serialize_document(db, doc)


@app.put("/api/letters/{letter_id}/iocs/{ioc_id}")
def ioc_update(letter_id: int, ioc_id: int, body: dict, request: Request,
               db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    ioc = db.query(IoC).filter(IoC.id == ioc_id, IoC.document_id == doc.id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC не найден")
    if "value" in body and str(body["value"]).strip():
        ioc.value = str(body["value"]).strip()
    if "ioc_type" in body:
        t = str(body["ioc_type"]).strip().lower()
        if t not in {"ip", "ipv6", "ip_cidr", "domain", "email", "hash", "bdu", "cve", "url"}:
            raise HTTPException(status_code=400, detail="Некорректный тип IoC")
        ioc.ioc_type = t
    _audit(db, user, "ioc_update", "ioc", ioc.id, ioc.value, doc.id, request=request)
    db.commit()
    return _serialize_document(db, doc)


@app.delete("/api/letters/{letter_id}/iocs/{ioc_id}")
def ioc_delete(letter_id: int, ioc_id: int, request: Request, db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    ioc = db.query(IoC).filter(IoC.id == ioc_id, IoC.document_id == doc.id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IoC не найден")
    db.delete(ioc)
    _audit(db, user, "ioc_delete", "ioc", ioc_id, document_id=doc.id, request=request)
    db.commit()
    return _serialize_document(db, doc)


@app.put("/documents/{doc_id}/vulnerabilities/{vuln_id}")
def vuln_update(doc_id: int, vuln_id: int, body: dict, request: Request,
                db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _update_vulnerability(db, user, doc_id, vuln_id, body, request=request)


@app.get("/api/letters/{letter_id}/export/{export_type}")
def legacy_export(letter_id: int, export_type: str, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    text = _build_export_text(export_type, iocs)
    if text is None:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")
    filename = _EXPORT_FILENAMES.get(export_type, f"{export_type}.txt")
    return Response(text.encode("utf-8"), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": _content_disposition(filename)})


@app.get("/api/letters/{letter_id}/export/{export_type}/docx")
def legacy_export_docx(letter_id: int, export_type: str, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    content = _build_export_text(export_type, iocs, docx=True)
    if content is None:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")
    filename = _EXPORT_DOCX_FILENAMES.get(export_type, f"{export_type}.docx")
    return Response(content, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": _content_disposition(filename)})


def _build_export_text(export_type: str, iocs, docx: bool = False):
    """Возвращает текст или bytes для вида экспорта, либо None для неизвестного типа."""
    if docx:
        from shared.generator.ioc_export_docx import export_ips_docx, export_domains_docx, \
            export_emails_docx, export_all_docx
        builders = {
            "emails": export_emails_docx, "ip_addresses": export_ips_docx,
            "domains": export_domains_docx, "ioc_indicators": export_all_docx,
        }
        fn = builders.get(export_type)
        return fn(iocs) if fn else None

    from shared.generator.ioc_export import export_emails, export_ips, export_domains, export_all
    builders = {
        "emails": export_emails, "ip_addresses": export_ips,
        "domains": export_domains, "ioc_indicators": export_all,
    }
    fn = builders.get(export_type)
    return fn(iocs) if fn else None


_EXPORT_FILENAMES = {
    "emails": "emails.txt",
    "ip_addresses": "ip-адреса на блокировку.txt",
    "domains": "Адреса на блокировку.txt",
    "ioc_indicators": "ioc_indicators.txt",
}

_EXPORT_DOCX_FILENAMES = {
    "emails": "emails.docx",
    "ip_addresses": "ip-адреса на блокировку.docx",
    "domains": "Адреса на блокировку.docx",
    "ioc_indicators": "ioc_indicators.docx",
}


@app.get("/api/letters/{letter_id}/download")
def legacy_download(letter_id: int, request: Request, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    if not resp:
        raise HTTPException(status_code=404, detail="Ответ ещё не сгенерирован")
    import io
    from docx import Document as DocxDocument
    if resp.edited_content:
        content = base64.b64decode(resp.edited_content)
    else:
        buf = io.BytesIO()
        d = DocxDocument()
        d.add_paragraph(resp.content or "")
        d.save(buf)
        content = buf.getvalue()
    _audit(db, user, "download_reply", "document", letter_id, document_id=letter_id, request=request)
    return Response(content, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": _content_disposition(f"answer_{letter_id}.docx")})


# ---------------- Templates (шаблоны и библиотека мер) ----------------

def _threat_type_dict(tt):
    return {"id": tt.id, "name": tt.name, "key": tt.key,
            "description": tt.description or "",
            "created_at": tt.created_at.isoformat() if tt.created_at else None}


def _measure_tpl_dict(mt):
    return {"id": mt.id, "name": mt.name, "threat_type_id": mt.threat_type_id,
            "measures": mt.content or "", "is_default": bool(mt.is_default),
            "created_at": mt.created_at.isoformat() if mt.created_at else None}


def _vuln_tpl_dict(vt):
    return {"id": vt.id, "name": vt.name, "vuln_type_id": None,
            "action_type": vt.action_type or "update", "content": vt.content or "",
            "is_default": bool(vt.is_default),
            "created_at": vt.created_at.isoformat() if vt.created_at else None}


@app.get("/api/templates/threat-types")
def list_threat_types(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_threat_type_dict(t) for t in db.query(ThreatType).order_by(ThreatType.id).all()]


@app.post("/api/templates/threat-types", status_code=201)
def create_threat_type(body: dict, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    name = (body.get("name") or "").strip()
    key = (body.get("key") or "").strip()
    if not name or not key:
        raise HTTPException(status_code=422, detail="name и key обязательны")
    if db.query(ThreatType).filter(ThreatType.name == name).first():
        raise HTTPException(status_code=409, detail="Тип угрозы с таким названием уже есть")
    if db.query(ThreatType).filter(ThreatType.key == key).first():
        raise HTTPException(status_code=409, detail="Тип угрозы с таким ключом уже есть")
    tt = ThreatType(name=name, key=key, description=(body.get("description") or "").strip())
    db.add(tt)
    db.commit()
    _audit(db, user, "threat_type_create", "threat_type", tt.id)
    return _threat_type_dict(tt)


@app.put("/api/templates/threat-types/{tt_id}")
def update_threat_type(tt_id: int, body: dict, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    tt = db.query(ThreatType).filter(ThreatType.id == tt_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    if "name" in body and body["name"]:
        tt.name = (body["name"] or "").strip()
    if "description" in body:
        tt.description = (body.get("description") or "")
    db.commit()
    _audit(db, user, "threat_type_update", "threat_type", tt.id)
    return _threat_type_dict(tt)


@app.delete("/api/templates/threat-types/{tt_id}")
def delete_threat_type(tt_id: int, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    tt = db.query(ThreatType).filter(ThreatType.id == tt_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    db.query(MeasureTemplate).filter(MeasureTemplate.threat_type_id == tt_id).delete(
        synchronize_session=False)
    db.delete(tt)
    db.commit()
    _audit(db, user, "threat_type_delete", "threat_type", tt_id)
    return {"status": "deleted"}


@app.get("/api/templates/measure-templates")
def list_measure_templates(threat_type_id: int | None = Query(None, ge=1, le=2_147_483_647),
                           db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    q = db.query(MeasureTemplate)
    if threat_type_id:
        q = q.filter(MeasureTemplate.threat_type_id == threat_type_id)
    return [_measure_tpl_dict(m) for m in q.order_by(MeasureTemplate.id).all()]


@app.post("/api/templates/measure-templates", status_code=201)
def create_measure_template(body: dict, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    content = (body.get("measures") if body.get("measures") not in (None, "")
               else body.get("content") or "")
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="name обязателен")
    mt = MeasureTemplate(name=name, threat_type_id=body.get("threat_type_id"),
                         content=str(content or ""), is_default=bool(body.get("is_default")))
    db.add(mt)
    db.commit()
    _audit(db, user, "measure_template_create", "measure_template", mt.id)
    return _measure_tpl_dict(mt)


@app.put("/api/templates/measure-templates/{mt_id}")
def update_measure_template(mt_id: int, body: dict, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    mt = db.query(MeasureTemplate).filter(MeasureTemplate.id == mt_id).first()
    if not mt:
        raise HTTPException(status_code=404, detail="Шаблон мер не найден")
    if "name" in body and body["name"]:
        mt.name = (body["name"] or "").strip()
    if "threat_type_id" in body:
        mt.threat_type_id = body["threat_type_id"]
    if body.get("measures") not in (None, ""):
        mt.content = str(body["measures"])
    elif "content" in body:
        mt.content = str(body.get("content") or "")
    if "is_default" in body:
        mt.is_default = bool(body.get("is_default"))
    db.commit()
    _audit(db, user, "measure_template_update", "measure_template", mt.id)
    return _measure_tpl_dict(mt)


@app.delete("/api/templates/measure-templates/{mt_id}")
def delete_measure_template(mt_id: int, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    mt = db.query(MeasureTemplate).filter(MeasureTemplate.id == mt_id).first()
    if not mt:
        raise HTTPException(status_code=404, detail="Шаблон мер не найден")
    db.delete(mt)
    db.commit()
    _audit(db, user, "measure_template_delete", "measure_template", mt_id)
    return {"status": "deleted"}


@app.get("/api/templates/vuln-templates")
def list_vuln_templates(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_vuln_tpl_dict(v) for v in db.query(VulnActionTemplate).order_by(VulnActionTemplate.id).all()]


@app.post("/api/templates/vuln-templates", status_code=201)
def create_vuln_template(body: dict, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="name обязателен")
    vt = VulnActionTemplate(name=name, action_type=(body.get("action_type") or "update").strip(),
                            content=(body.get("content") or "").strip(),
                            is_default=bool(body.get("is_default")))
    db.add(vt)
    db.commit()
    _audit(db, user, "vuln_template_create", "vuln_action_template", vt.id)
    return _vuln_tpl_dict(vt)


@app.put("/api/templates/vuln-templates/{vt_id}")
def update_vuln_template(vt_id: int, body: dict, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    vt = db.query(VulnActionTemplate).filter(VulnActionTemplate.id == vt_id).first()
    if not vt:
        raise HTTPException(status_code=404, detail="Шаблон уязвимости не найден")
    if "name" in body and body["name"]:
        vt.name = (body["name"] or "").strip()
    if "action_type" in body:
        vt.action_type = (body.get("action_type") or "update").strip()
    if "content" in body:
        vt.content = str(body.get("content") or "")
    if "is_default" in body:
        vt.is_default = bool(body.get("is_default"))
    db.commit()
    _audit(db, user, "vuln_template_update", "vuln_action_template", vt.id)
    return _vuln_tpl_dict(vt)


@app.delete("/api/templates/vuln-templates/{vt_id}")
def delete_vuln_template(vt_id: int, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    vt = db.query(VulnActionTemplate).filter(VulnActionTemplate.id == vt_id).first()
    if not vt:
        raise HTTPException(status_code=404, detail="Шаблон уязвимости не найден")
    db.delete(vt)
    db.commit()
    _audit(db, user, "vuln_template_delete", "vuln_action_template", vt_id)
    return {"status": "deleted"}


# ---------------- Diagnostics ----------------

def _probe_http(url: str, timeout: float = 3.0, insecure: bool = False) -> dict:
    """Проверка доступности хоста. «Доступен» = получен любой HTTP-ответ (включая 4xx/5xx),
    недоступен — только транспортные ошибки (DNS, таймаут, TLS, refused)."""
    import urllib.error
    import urllib.request
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "fstec-diagnostics"})
        context = None
        if insecure:
            import ssl
            context = ssl._create_unverified_context()
        with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
            return {"reachable": True, "http_status": resp.status,
                    "latency_ms": round((time.time() - start) * 1000), "error": ""}
    except urllib.error.HTTPError as e:  # сервер ответил не-2xx — хост доступен
        return {"reachable": True, "http_status": e.code,
                "latency_ms": round((time.time() - start) * 1000),
                "error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "http_status": None,
                "latency_ms": round((time.time() - start) * 1000),
                "error": str(e)[:160]}


def _db_health(db: Session) -> dict:
    from sqlalchemy import text
    start = time.time()
    try:
        db.execute(text("SELECT 1")).scalar()
        return {"name": "База данных", "reachable": True,
                "latency_ms": round((time.time() - start) * 1000), "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"name": "База данных", "reachable": False,
                "latency_ms": round((time.time() - start) * 1000),
                "error": str(e)[:160]}


def _services_with_heartbeat() -> list[dict]:
    from shared.registry import read_services
    now = time.time()
    out = []
    for s in read_services():
        lt = s.get("last_seen")
        out.append({**s, "pid_exists": bool(s.get("alive")),
                    "heartbeat_age_sec": int(now - lt) if lt else None})
    return out


@app.get("/api/diagnostics")
def diagnostics(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Статус модулей, БД, внешних подключений, LLM и ресурсов (для страницы «Диагностика»)."""
    from shared.config import (BDU_API_BASE, CMDB_ENDPOINT, CMDB_PROVIDER,
                               LLM_PROVIDER, NVD_API_BASE, VLLM_BASE_URL, VLLM_MODEL)
    from shared.registry import touch_service
    import psutil

    touch_service("gateway")
    services = _services_with_heartbeat()

    # Проверки выполняются сервером (gateway), а не браузером.
    external = [{"name": "BDU ФСТЭК", "url": f"{BDU_API_BASE.rstrip('/')}/",
                 **_probe_http(f"{BDU_API_BASE.rstrip('/')}/", timeout=4.0)}]
    # NVD отдаёт большой JSON; проверяем доступность корня API
    external.append({"name": "NVD (NIST)", "url": f"{NVD_API_BASE}/rest/json/cves/2.0?resultsPerPage=1",
                     **_probe_http(f"{NVD_API_BASE}/rest/json/cves/2.0?resultsPerPage=1", timeout=4.0)})
    if CMDB_PROVIDER == "glpi":
        from shared.config import GLPI_API, GLPI_URL
        probe = (_probe_http(f"{GLPI_URL}/apirest.php/", timeout=4.0)
                 if GLPI_API == "v1" else _probe_http(f"{GLPI_URL}/api.php/token", timeout=4.0))
        external.append({"name": "GLPI (CMDB ПО)", "url": f"{GLPI_URL}/", **probe})
    elif CMDB_PROVIDER != "mock":
        external.append({"name": "CMDB (rest)", "url": CMDB_ENDPOINT,
                         **_probe_http(CMDB_ENDPOINT, timeout=4.0)})
    else:
        external.append({"name": "CMDB (rest)", "url": CMDB_ENDPOINT, "reachable": True,
                         "http_status": None, "latency_ms": 0,
                         "error": "провайдер 'mock' (внешний запрос не выполняется)"})

    from shared.config import IOC_CLASSIFIER_URL
    if IOC_CLASSIFIER_URL:
        bert_health = IOC_CLASSIFIER_URL.rsplit("/", 1)[0] + "/health"
        bert_health = bert_health.replace("host.docker.internal", "172.17.0.1")
        external.append({"name": "BERT IoC", "url": bert_health,
                         **_probe_http(bert_health, timeout=3.0, insecure=True)})

    llm_probe = _probe_http(f"{VLLM_BASE_URL}/models", timeout=2.0, insecure=True)
    llm = {
        "provider": LLM_PROVIDER,
        "base_url": VLLM_BASE_URL,
        "model": VLLM_MODEL,
        "reachable": llm_probe["reachable"],
        "http_status": llm_probe["http_status"],
        "latency_ms": llm_probe["latency_ms"],
        "error": llm_probe["error"],
        "note": ("heuristic-режим: LLM не вызывается (dev). Для реальных вызовов укажите "
                 "FSTEC_LLM_PROVIDER=vllm") if LLM_PROVIDER != "vllm" else "",
    }

    proc = psutil.Process()
    disk = psutil.disk_usage(str(Path(__file__).resolve().parent.parent))
    system = {
        "cpu_percent": psutil.cpu_percent(interval=0.4),
        "memory_mb": round(psutil.virtual_memory().used / 1048576),
        "memory_total_mb": round(psutil.virtual_memory().total / 1048576),
        "disk_free_gb": round(disk.free / 1073741824, 1),
        "gateway_proc_cpu_percent": proc.cpu_percent(interval=0.2),
        "gateway_proc_memory_mb": round(proc.memory_info().rss / 1048576),
        "gateway_uptime_sec": int(time.time() - proc.create_time()),
    }
    from shared.config import GATEWAY_PORT
    gw_probe = _probe_http(f"http://127.0.0.1:{GATEWAY_PORT}/api/health", timeout=2.0)
    return {"services": services, "external": external, "db": _db_health(db),
            "llm": llm, "system": system,
            "gateway": {"name": "gateway", "reachable": gw_probe["reachable"],
                        "http_status": gw_probe["http_status"],
                        "latency_ms": gw_probe["latency_ms"], "error": gw_probe["error"]}}


@app.get("/api/diagnostics/ping")
def diagnostics_ping(name: str | None = Query(default=None, max_length=64),
                     db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Активный «пинг» модулей (или одного), БД и самого gateway."""
    from shared.config import GATEWAY_PORT

    def _ok(service: dict) -> bool:
        return bool(service.get("pid_exists")) and (service.get("heartbeat_age_sec") or 0) <= 60

    now = time.time()
    services = []
    for s in _services_with_heartbeat():
        if name and s["name"] != name:
            continue
        services.append({
            "name": s["name"], "pid": s["pid"], "pid_exists": s["pid_exists"],
            "alive": s["alive"], "heartbeat_age_sec": s["heartbeat_age_sec"],
            "ok": _ok(s), "latency_ms": None,
        })

    gw = _probe_http(f"http://127.0.0.1:{GATEWAY_PORT}/api/health", timeout=2.0)
    for s in services:
        if s["name"] == "gateway":
            s["ok"] = gw["reachable"]
            s["latency_ms"] = gw["latency_ms"]
    return {"pinged_at": round(now), "name_sent": name or None,
            "services": services, "db": _db_health(db),
            "gateway": {"ok": gw["reachable"], "latency_ms": gw["latency_ms"],
                        "error": gw["error"]}}


def _bus_sqlite(db: Session) -> dict:
    from sqlalchemy import text
    total = db.execute(text("SELECT COUNT(*) FROM bus_message")).scalar() or 0
    topics = db.execute(text(
        "SELECT topic, COUNT(*) AS c, MAX(id) AS last_id FROM bus_message GROUP BY topic")).fetchall()
    rows = [{"topic": t[0], "count": t[1], "last_id": t[2]} for t in topics]
    return {"backend": "sqlite", "total": total, "topics": rows}


def _bus_kafka() -> dict:
    """Счётчики топиков Kafka: число сообщений (end offsets) и последний offset.

    Лёгкий consumer без подписки — только метаданные и end offsets. Партиции
    одной темы суммируются; служебные топики («__consumer_offsets») скрываются.
    """
    import asyncio

    from shared.config import KAFKA_BOOTSTRAP
    from shared.bus import kafka_security_kwargs

    async def _collect() -> list:
        from aiokafka import AIOKafkaConsumer, TopicPartition
        consumer = AIOKafkaConsumer(bootstrap_servers=KAFKA_BOOTSTRAP,
                                    client_id="fstec-diagnostics",
                                    **kafka_security_kwargs())
        await consumer.start()
        try:
            topics = sorted(t for t in await consumer.topics() if not t.startswith("__"))
            rows = []
            for t in topics:
                parts = consumer.partitions_for_topic(t) or set()
                if not parts:
                    continue
                tps = [TopicPartition(t, p) for p in sorted(parts)]
                ends = await consumer.end_offsets(tps)
                vals = [int(v) for v in ends.values()]
                rows.append({"topic": t, "count": sum(vals),
                             "last_id": max(vals, default=0)})
            return rows
        finally:
            await consumer.stop()

    rows = asyncio.run(asyncio.wait_for(_collect(), timeout=6))
    return {"backend": "kafka", "total": sum(r["count"] for r in rows), "topics": rows}


@app.get("/api/diagnostics/bus")
def diagnostics_bus(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Статус очереди сообщений: Kafka (prod) / SQLite (dev-шина)."""
    from shared.config import EVENT_BUS
    try:
        if EVENT_BUS == "kafka":
            return _bus_kafka()
        if EVENT_BUS == "sqlite":
            return _bus_sqlite(db)
        return {"backend": EVENT_BUS, "total": 0, "topics": [],
                "error": "шина в памяти: счётчики не сохраняются"}
    except Exception as e:  # noqa: BLE001
        return {"backend": EVENT_BUS, "total": 0, "topics": [], "error": str(e)[:160]}


_FRONTEND_DIR = Path(os.environ.get(
    "FSTEC_FRONTEND_DIR", str(Path(__file__).resolve().parents[2] / "frontend")
))
if _FRONTEND_DIR.is_dir():
    app.mount("/verify", StaticFiles(directory=str(_FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    from shared.config import GATEWAY_PORT
    from shared.registry import register_service
    register_service("gateway")
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)
