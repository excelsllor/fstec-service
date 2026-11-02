"""Watchdog: показывает/помечает документы, зависшие в нетерминальном статусе.

Примеры:
  python tools/watchdog.py --older-than 30
  python tools/watchdog.py --older-than 30 --mark-failed
"""
import argparse
import os
from datetime import datetime, timedelta, timezone

from shared.db import SessionLocal
from shared.models import Document

TERMINAL = ("completed", "failed", "error", "deleted")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--older-than", type=int, default=30, help="минут с последнего обновления")
    parser.add_argument("--mark-failed", action="store_true", help="пометить найденные документы failed")
    parser.add_argument("--since", default="", help="не трогать документы с updated_at раньше ISO-времени")
    args = parser.parse_args()

    cutoff = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(minutes=args.older_than)
    since = None
    if args.since:
        since = datetime.fromisoformat(args.since)
        if since.tzinfo is not None:
            since = since.astimezone(timezone.utc).replace(tzinfo=None)
    with SessionLocal() as db:
        query = (db.query(Document)
                 .filter(~Document.status.in_(TERMINAL), Document.updated_at < cutoff))
        if since is not None:
            query = query.filter(Document.updated_at >= since)
        rows = query.order_by(Document.updated_at).all()
        if not rows:
            print(f"OK: нет документов старше {args.older_than} мин в нетерминальном статусе")
            return
        print(f"Найдено {len(rows)} зависших документов:")
        for d in rows:
            print(f"  id={d.id} status={d.status} stage={d.processing_stage} "
                  f"updated={d.updated_at} file={d.source_filename}")
            if args.mark_failed:
                d.status = "failed"
                d.processing_stage = "failed"
                note = f"watchdog: stuck > {args.older_than} min"
                d.parse_errors = "; ".join(x for x in (d.parse_errors, note) if x)
        if args.mark_failed:
            db.commit()
            print(f"Помечено failed: {len(rows)}")


if __name__ == "__main__":
    main()
