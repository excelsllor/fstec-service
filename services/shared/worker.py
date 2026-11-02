"""Общие хелперы запуска воркеров (подписка + удержание цикла)."""
import asyncio
import logging
from typing import Mapping

from shared.bus import EventBus, Handler

logger = logging.getLogger(__name__)


def register_handlers(bus: EventBus, handlers: Mapping[str, Handler]) -> None:
    for topic, handler in handlers.items():
        bus.subscribe(topic, handler)


async def serve_forever(bus: EventBus, heartbeat_name: str | None = None, heartbeat_s: float = 15.0):
    """Бесконечный цикл воркера (Kafka/sqlite-шина). memory-шина не нуждается в цикле."""
    await bus.start()
    logger.info("Worker started on %s bus", type(bus).__name__)
    if heartbeat_name:
        from shared.registry import touch_service

        async def _beat():
            while True:
                try:
                    touch_service(heartbeat_name)
                except Exception:
                    logger.warning("heartbeat write failed for %s", heartbeat_name, exc_info=True)
                await asyncio.sleep(heartbeat_s)

        asyncio.create_task(_beat())
    await asyncio.Event().wait()


def configure_logging(level: int = logging.INFO):
    logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")