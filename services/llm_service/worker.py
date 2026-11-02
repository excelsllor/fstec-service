"""LLM Service (РўР— 2.3): document.parsed в†’ Р°РЅР°Р»РёР· в†’ document.analyzed."""
import asyncio
import logging

from shared.bus import get_event_bus
from shared.concurrency import run_blocking
from shared.config import LLM_WARMUP_ENABLED, LLM_WARMUP_INTERVAL_S
from shared.db import SessionLocal, init_db
from shared.models import Document
from shared.worker import configure_logging, register_handlers, serve_forever
from llm_service.analyze import analyze_async, compute_sla, persist_analysis
from llm_service.provider import get_provider
from llm_service.rubert import get_rubert

try:  # pooled-клиенты есть только в async-провайдере; sync- Fallback без них
    from llm_service.provider import close_provider_clients
except ImportError:  # pragma: no cover
    close_provider_clients = None

logger = logging.getLogger("fstec.llm")


def _persist(doc_id: int, event_data) -> bool:
    """Синхронная запись в БД — выполняется в потоке, чтобы не блокировать петлю.
    False — документа в БД нет, событие downstream публиковать нельзя."""
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip analysis", doc_id)
            return False
        persist_analysis(db, doc, event_data)
        sla, routing = compute_sla(
            classification=event_data.classification,
            threat_count=len(event_data.threats),
            vuln_severities=[v.get("severity", "unknown") for v in event_data.vulns_raw],
            domain_count=len(event_data.iocs.domains),
        )
        doc.sla, doc.routing = sla, routing
        db.commit()
        event_data.sla = sla
        event_data.routing = routing
    return True


async def handle_parsed(topic: str, key: str, payload: dict) -> None:
    import time as _tt
    _start = _tt.time()
    logger.info("TRACE handle_parsed start key=%s", key)
    doc_id = int(payload["document_id"])
    text = (payload.get("all_text") or payload.get("text") or "")
    if not text.strip():
        # Сообщение всё равно будет закоммичено (обработчик не падает), поэтому
        # нельзя оставлять документ в 'parsed' навсегда — помечаем failed.
        logger.warning("Empty text for doc %s, mark failed", doc_id)
        with SessionLocal() as db:
            doc = db.query(Document).filter(Document.id == doc_id).first()
            if doc and doc.status not in ("completed", "failed"):
                doc.status = "failed"
                doc.processing_stage = "failed"
                db.commit()
        return
    provider = get_provider()
    event_data, _ = await analyze_async(provider, text)
    event_data.document_id = doc_id

    if not await run_blocking(_persist, doc_id, event_data):
        return

    await get_event_bus().publish("document.analyzed", str(doc_id), event_data.model_dump(mode="json"))
    logger.info("Analyzed doc %s: %s, %d threats, %d iocs", doc_id,
                event_data.classification, len(event_data.threats),
                len(event_data.iocs.ip_addresses) + len(event_data.iocs.domains))


async def _warmup_loop(provider) -> None:
    """Держит vLLM «горячим» и заранее загружает RuBERT."""
    if not LLM_WARMUP_ENABLED:
        return
    warm_vllm = getattr(provider, "kind", None) == "vllm"
    rubert_done = False
    while True:
        vllm_ok = not warm_vllm
        if warm_vllm:
            try:
                elapsed = await provider.warmup_async()
                logger.info("vLLM warmup ok in %.2fs", elapsed)
                vllm_ok = True
            except Exception as exc:  # noqa: BLE001
                logger.warning("vLLM warmup failed: %s: %s", type(exc).__name__, exc)
        if not rubert_done:
            try:
                clf = await run_blocking(get_rubert)
                rubert_done = clf is not None
                logger.info("RuBERT warmup: %s", "loaded" if rubert_done else "unavailable")
            except Exception as exc:  # noqa: BLE001
                logger.warning("RuBERT warmup failed: %s: %s", type(exc).__name__, exc)
        await asyncio.sleep(LLM_WARMUP_INTERVAL_S if vllm_ok else 10.0)


def main():
    configure_logging()
    from shared.registry import register_service
    register_service("llm")
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"document.parsed": handle_parsed})
        asyncio.create_task(_warmup_loop(get_provider()))
        try:
            await serve_forever(bus, heartbeat_name="llm")
        finally:
            if close_provider_clients is not None:
                await close_provider_clients()
    asyncio.run(_run())


if __name__ == "__main__":
    main()