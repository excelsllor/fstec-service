"""Ingest Service (РўР— 2.2): РїР°СЂСЃРёРЅРі + OCR в†’ document.parsed."""
import asyncio
import json
import logging
from pathlib import Path

from shared.bus import get_event_bus
from shared.concurrency import run_blocking
from shared.config import OCR_ENABLED, OCR_MIN_TEXT, OCR_LANG
from shared.db import SessionLocal
from shared.events import DocumentParsed
from shared.models import Attachment, Document, DocumentTable
from shared.parsers import parse_file
from shared.parsers.ocr import (ocr_docx_bytes, ocr_embedded_images_bytes,
                                ocr_office_bytes, ocr_pdf_bytes)
from shared.worker import configure_logging, register_handlers

logger = logging.getLogger("fstec.ingest")


def _parse_document(doc_id: int) -> DocumentParsed | None:
    """Разбор вложений + OCR + запись в БД. Полностью синхронная и тяжёлая
    функция — вызывается через run_blocking, чтобы event loop воркера продолжал
    принимать события (этап 4). Сессия БД живёт только здесь и закрывается до
    публикации события. None — документа/вложений нет."""
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip ingest", doc_id)
            return None
        attachments = (db.query(Attachment)
                       .filter(Attachment.document_id == doc_id)
                       .order_by(Attachment.is_main.desc())
                       .order_by(Attachment.id).all())
        if not attachments:
            logger.warning("No attachments for doc %s", doc_id)
            return None

        db.query(DocumentTable).filter(DocumentTable.document_id == doc_id).delete()
        main_text = ""
        all_texts: list[str] = []
        ocr_used = False
        parse_errors: list[str] = []
        att_meta = []

        for att in attachments:
            path = Path(att.file_path)
            try:
                result = parse_file(path)
            except Exception as exc:
                att.parse_status = "error"
                att.parse_errors = str(exc)
                parse_errors.append(f"{att.filename}: {exc}")
                continue

            text = result.text or ""
            if result.tables:
                table_lines = []
                for table in result.tables:
                    for row in table:
                        cells = [str(c).strip() for c in row if str(c).strip()]
                        if cells:
                            table_lines.append(" | ".join(cells))
                table_text = "\n".join(table_lines)
                if table_text and table_text not in text:
                    text = (text.rstrip() + "\n\n" + table_text).strip()
            page_texts = result.page_texts or []
            needs_page_ocr = bool(page_texts) and any(
                len((p or "").strip()) < OCR_MIN_TEXT for p in page_texts
            )
            if OCR_ENABLED and (len(text.strip()) < OCR_MIN_TEXT or needs_page_ocr):
                try:
                    content = path.read_bytes()
                    if att.file_type == ".pdf":
                        text, ocr_errors = ocr_pdf_bytes(content, lang=OCR_LANG)
                    elif att.file_type in (".doc", ".docx", ".rtf"):
                        text, ocr_errors = ocr_office_bytes(content, att.file_type, lang=OCR_LANG)
                        if not text.strip():
                            if att.file_type == ".docx":
                                text, extra = ocr_docx_bytes(content, lang=OCR_LANG)
                            else:
                                text, extra = ocr_embedded_images_bytes(content, lang=OCR_LANG)
                            ocr_errors.extend(extra or [])
                    else:
                        continue
                    if text.strip():
                        ocr_used = True
                    parse_errors.extend(f"OCR {att.filename}: {e}" for e in ocr_errors)
                    logger.info("OCR applied to %s (chars=%d)", att.filename, len(text))
                except Exception as exc:
                    parse_errors.append(f"OCR {att.filename}: {exc}")

            for ti, table in enumerate(result.tables or []):
                db.add(DocumentTable(document_id=doc.id, table_index=ti,
                                     rows_json=json.dumps(table, ensure_ascii=False)))
            att.parsed_text = text
            att.parse_status = "done" if text.strip() else "empty"
            all_texts.append(text)
            if att.is_main:
                main_text = text
            att_meta.append({"filename": att.filename, "text_len": len(text), "status": att.parse_status})

        doc.original_text = main_text or (all_texts[0] if all_texts else "")
        doc.all_text = "\n\n".join(t for t in all_texts if t.strip())
        doc.ocr_used = ocr_used
        doc.processing_stage = "parsed"
        doc.status = "parsed"
        doc.parse_errors = "; ".join(parse_errors)
        db.commit()

        return DocumentParsed(
            document_id=doc_id,
            text=main_text or (all_texts[0] if all_texts else ""),
            all_text="\n\n".join(t for t in all_texts if t.strip()),
            ocr_used=ocr_used,
            parse_errors=parse_errors,
            attachments=att_meta,
        )


async def handle_uploaded(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    event = await run_blocking(_parse_document, doc_id)
    if event is None:
        return
    await get_event_bus().publish("document.parsed", str(doc_id), event.model_dump(mode="json"))
    logger.info("Parsed doc %s: %d attachments, %d chars", doc_id, len(event.attachments),
                len(event.all_text))


def main():
    configure_logging()
    from shared.registry import register_service
    register_service("ingest")
    asyncio.run(run_service())


async def run_service():
    bus = get_event_bus()
    register_handlers(bus, {"documents.uploaded": handle_uploaded})
    from shared.worker import serve_forever
    await serve_forever(bus, heartbeat_name="ingest")


if __name__ == "__main__":
    main()