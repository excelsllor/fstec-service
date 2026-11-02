"""Сквозной тест: upload → parsed → analyzed → assessed → report+reply
на MemoryEventBus (детерминированная цепочка в одном asyncio-цикле)."""
import asyncio

from shared.bus import get_event_bus
from shared.db import SessionLocal
from shared.events import DocumentsUploaded
from shared.models import (Attachment, Document, GeneratedResponse, IoC,
                              Report, Threat, Vulnerability)
from shared.worker import register_handlers
from ingest_service.worker import handle_uploaded as ingest_handler
from llm_service.worker import handle_parsed as llm_handler
from security_service.worker import handle_analyzed as security_handler
from reporting_service.worker import handle_assessed as reporting_handler
from conftest import create_uploaded_document, make_docx_bytes


def _run_chain(doc_id: int):
    async def run():
        bus = get_event_bus()
        register_handlers(bus, {
            "documents.uploaded": ingest_handler,
            "document.parsed": llm_handler,
            "document.analyzed": security_handler,
            "security.assessed": reporting_handler,
        })
        await bus.publish("documents.uploaded", str(doc_id), DocumentsUploaded(
            document_id=doc_id, main_file={"filename": "letter.docx", "path": "",
                                           "size": 0},
        ).model_dump(mode="json"))
    asyncio.run(run())


def test_full_pipeline(tmp_path):
    doc_id = create_uploaded_document(tmp_path, "letter.docx", make_docx_bytes())
    _run_chain(doc_id)

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        assert doc.status == "completed"
        assert doc.processing_stage == "done"
        assert doc.letter_type == "hacker"
        assert doc.letter_number == "456/1"
        assert doc.letter_date == "2024-03-15"
        assert doc.sla == "critical"
        assert doc.routing == "infosec"
        assert doc.all_text and "Rare Werewolf" in doc.all_text

        threats = db.query(Threat).filter(Threat.document_id == doc_id).all()
        assert len(threats) == 2
        assert any(t.group_name == "Rare Werewolf" for t in threats)
        assert any(t.threat_type == "vulnerability" for t in threats)

        iocs = db.query(IoC).filter(IoC.document_id == doc_id).all()
        types = {i.ioc_type for i in iocs}
        assert "ip" in types and "domain" in types and "email" in types
        assert "cve" in types and "bdu" in types
        values = {i.value for i in iocs}
        assert "203.0.113.10:8080" in values
        assert "CVE-2021-44228" in values

        vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()
        assert vulns, "должны быть сохранены оценённые уязвимости"
        assert all(v.cmdb_match for v in vulns)
        assert any(v.software == "Apache Log4j" for v in vulns)
        assert all(v.current_version for v in vulns)

        report = db.query(Report).filter(Report.document_id == doc_id).first()
        assert report is not None
        assert report.filename.startswith("Report_letter_")
        assert report.file_path

        resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc_id) \
            .order_by(GeneratedResponse.id.desc()).first()
        assert resp is not None
        assert "BDU:2024-12345" in resp.content
        assert "С уважением" not in resp.content


def test_no_threat_document(tmp_path):
    """Письмо без угроз → зелёный статус, ответ «не подвержено риску»."""
    from conftest import SAMPLE_TEXT
    clean = SAMPLE_TEXT.split("Сообщаем Вам о следующих угрозах:")[0]
    doc_id = create_uploaded_document(tmp_path, "clean.docx", make_docx_bytes(clean))
    _run_chain(doc_id)
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        assert doc.status == "completed"
        resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc_id) \
            .order_by(GeneratedResponse.id.desc()).first()
        assert "не подвержено риску" in resp.content