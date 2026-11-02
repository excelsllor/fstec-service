"""Саммари обязано генерироваться и сохраняться в БД (таблица summaries)
независимо от провайдера: heuristic (confidence 0.6) и vllm/LLM (0.9)."""
from llm_service.analyze import analyze, persist_analysis
from llm_service.provider import LLMResult
from shared.db import SessionLocal
from shared.models import Document, IoC, Summary

from conftest import create_uploaded_document

SAMPLE = (
    "Управление ФСТЭК России, исходящий № 456/1 от 15 марта 2024 г.\n"
    "Хакерской группировкой Rare Werewolf проводится целевая атака с рассылкой "
    "фишинговых писем с архивом doc.zip с адресов evil[.]com и 203.0.113.10.\n"
    "Необходимо обновить антивирусные базы в течение 3 дней.\n"
)

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class _FakeVLLM:
    def __init__(self, classification="hacker", summary="Саммари от LLM, не менее нужной длины текста"):
        self._cls, self._sum = classification, summary

    def analyze(self, text, hint=None):
        return LLMResult(classification=self._cls, summary=self._sum, llm_used=True)


def _persisted(doc_id):
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        row = db.query(Summary).filter(Summary.document_id == doc_id).first()
        return doc, row


def test_heuristic_summary_persisted(tmp_path):
    doc_id = create_uploaded_document(tmp_path)
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        from llm_service.provider import get_provider
        event, _ = analyze(get_provider(), SAMPLE)
        persist_analysis(db, doc, event)
    doc, row = _persisted(doc_id)
    assert doc.processing_stage == "analyzed"
    assert row is not None
    assert row.confidence == 0.6
    assert row.summary and len(row.summary.strip()) > 0


def test_vllm_summary_persisted_with_confidence_09(tmp_path):
    doc_id = create_uploaded_document(tmp_path)
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        event, _ = analyze(_FakeVLLM(), SAMPLE)
        persist_analysis(db, doc, event)
    doc, row = _persisted(doc_id)
    assert doc.letter_type == "hacker"
    assert row is not None
    assert row.confidence == 0.9
    assert row.summary.startswith("Саммари от LLM")


def test_hash_iocs_persisted(tmp_path):
    """SHA256 из письма обязан попасть в iocs (раньше терялся на этапе события)."""
    doc_id = create_uploaded_document(tmp_path)
    text = SAMPLE + f"\nХэш-сумма вредоносного файла: {SHA256}\n"
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        from llm_service.provider import get_provider
        event, _ = analyze(get_provider(), text)
        persist_analysis(db, doc, event)
        rows = db.query(IoC).filter(IoC.document_id == doc_id, IoC.ioc_type == "hash").all()
    assert any(r.value == SHA256 for r in rows)