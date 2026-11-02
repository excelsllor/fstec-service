"""Audit consumer: audit.events -> audit_log (at-least-once)."""
import asyncio
import logging
from datetime import datetime

from shared.bus import get_event_bus
from shared.concurrency import run_blocking
from shared.db import SessionLocal, init_db
from shared.models import AuditLog
from shared.worker import configure_logging, register_handlers, serve_forever

logger = logging.getLogger("fstec.audit")


def _persist(payload: dict) -> None:
    def _int(value):
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    created_at = None
    raw_created = payload.get("created_at")
    if raw_created:
        try:
            created_at = datetime.fromisoformat(str(raw_created).replace("Z", "+00:00"))
        except ValueError:
            created_at = None

    with SessionLocal() as db:
        rec = AuditLog(
            user_id=_int(payload.get("user_id")),
            username=str(payload.get("username") or "")[:100],
            action=str(payload.get("action") or "audit_event")[:50],
            object_type=str(payload.get("object_type") or "")[:50],
            object_id=_int(payload.get("object_id")),
            filename=str(payload.get("filename") or "")[:500],
            document_id=_int(payload.get("document_id")),
            ip_address=str(payload.get("ip_address") or "")[:45],
        )
        if created_at is not None:
            rec.created_at = created_at
        db.add(rec)
        db.commit()


async def handle_audit(topic: str, key: str, payload: dict) -> None:
    if not isinstance(payload, dict):
        logger.warning("Skip non-dict audit event key=%s", key)
        return
    await run_blocking(_persist, payload)


def main():
    configure_logging()
    from shared.registry import register_service

    register_service("audit")

    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"audit.events": handle_audit})
        await serve_forever(bus, heartbeat_name="audit")

    asyncio.run(_run())


if __name__ == "__main__":
    main()
