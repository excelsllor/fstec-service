"""Сквозной live-сценарий Фазы 3: worker + фейковые NVD/BDU + MockCMDB →
обогащение в БД, источник, эскалация SLA, DLQ при недоступности внешних БД (ТЗ 4.2)."""
import asyncio
from typing import Awaitable, Callable

from shared.bus import get_event_bus
from shared.db import SessionLocal
from shared.models import Document, Vulnerability
from security_service.cmdb_mock import MockCMDB
from security_service.worker import handle_analyzed, set_test_clients
from conftest import create_uploaded_document
from tests.fakes import VULN_RAW, FakeBDUClient, FakeNVDClient


def _run(fn):
    return asyncio.run(fn)


def _collector(bucket: list) -> Callable[[str, str, dict], Awaitable[None]]:
    async def _on(topic: str, key: str, payload: dict):
        bucket.append(payload)
    return _on


def test_live_assess_stores_enriched(tmp_path):
    doc_id = create_uploaded_document(tmp_path, "sec.docx")
    failed = []
    get_event_bus().subscribe("documents.failed", _collector(failed))
    set_test_clients(nvd=FakeNVDClient(), bdu=FakeBDUClient(), cmdb=MockCMDB())
    _run(handle_analyzed("document.analyzed", str(doc_id),
                         {"document_id": doc_id, "vulns_raw": [dict(VULN_RAW)]}))
    set_test_clients()

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        assert doc.processing_stage in ("assessed", "done")   # reporting может уйти дальше
        assert doc.sla == "critical"
        assert doc.routing == "infosec"
        vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()
        assert len(vulns) == 1
        v = vulns[0]
        assert v.source == "bdu"                       # для BDU-письма BDU — источник истины
        assert v.cmdb_match is True
        assert v.current_version == "2.15.0"
        assert v.target_version == "2.17.0"            # фикс из BDU/описания
        assert v.cvss_score == 9.8
        assert v.cpe.startswith("cpe:2.3:a:apache:log4j")
    assert failed == []


def test_dlq_on_external_failure(tmp_path):
    doc_id = create_uploaded_document(tmp_path, "sec.docx")
    failed, audited = [], []
    bus = get_event_bus()
    bus.subscribe("documents.failed", _collector(failed))
    bus.subscribe("audit.events", _collector(audited))
    set_test_clients(nvd=FakeNVDClient(fail=True), bdu=FakeBDUClient(fail=True),
                     cmdb=MockCMDB())
    _run(handle_analyzed("document.analyzed", str(doc_id),
                         {"document_id": doc_id, "vulns_raw": [dict(VULN_RAW)]}))
    set_test_clients()

    assert failed and failed[0]["document_id"] == doc_id
    assert failed[0]["stage"] == "security.assessed"
    assert any(a["action"] == "external_security_error" for a in audited)
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        assert doc.processing_stage in ("assessed", "done")   # документ не упал (graceful)
        vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()
        assert vulns and vulns[0].source == "manual"   # raw из письма, keep-all