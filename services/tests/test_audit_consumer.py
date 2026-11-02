import asyncio

from audit_service.worker import handle_audit
from shared.db import SessionLocal
from shared.models import AuditLog


def test_audit_event_persisted():
    payload = {
        "event": "audit.events",
        "username": "security-service",
        "action": "external_security_error",
        "object_type": "document",
        "object_id": 424242,
        "document_id": 424242,
        "ip_address": "127.0.0.1",
        "created_at": "2026-10-24T12:00:00+00:00",
    }
    asyncio.run(handle_audit("audit.events", "424242", payload))
    with SessionLocal() as db:
        rec = db.query(AuditLog).filter(AuditLog.document_id == 424242).first()
        assert rec is not None
        assert rec.action == "external_security_error"
        assert rec.username == "security-service"
        assert rec.object_id == 424242


def test_audit_event_defaults_and_truncation():
    payload = {"action": "x" * 100, "filename": "y" * 700}
    asyncio.run(handle_audit("audit.events", "k", payload))
    with SessionLocal() as db:
        rec = db.query(AuditLog).filter(AuditLog.filename == "y" * 500).first()
        assert rec is not None
        assert len(rec.action) == 50
