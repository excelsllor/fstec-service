"""Устойчивость внешних вызовов (ТЗ 4.2): ретраи ≤3 с экспоненциальной задержкой и jitter,
исчерпание попыток → ExternalServiceError (обрабатывается caller'ом, документ не падает)."""
import asyncio
import logging
import random

from shared.config import SECURITY_RETRY_MAX

logger = logging.getLogger("fstec.security.resilience")


class ExternalServiceError(Exception):
    """Недоступность внешнего сервиса после исчерпания ретраев."""


def backoff_seconds(attempt: int, base: tuple[int, ...] = (1, 2, 4)) -> float:
    delay = float(base[min(attempt, len(base) - 1)])
    return delay * (1 + random.random() * 0.2)


async def retry_async(afn, *args, attempts: int | None = None, **kwargs):
    """Вызывает afn с ретраями (attempts по умолчанию из конфига), бросает ExternalServiceError."""
    attempts = attempts if attempts is not None else SECURITY_RETRY_MAX
    if attempts < 1:
        attempts = 1
    last_exc: Exception | None = None
    for i in range(attempts):
        try:
            return await afn(*args, **kwargs)
        except Exception as exc:  # noqa: BLE001 — внешние вызовы могут падать как угодно
            last_exc = exc
            if i < attempts - 1:
                delay = backoff_seconds(i)
                logger.warning("external call %s failed (%s/%s): %s; retry in %.2fs",
                               getattr(afn, "__name__", afn), i + 1, attempts, exc, delay)
                await asyncio.sleep(delay)
    raise ExternalServiceError(f"{getattr(afn, '__name__', afn)} failed after {attempts} attempts: {last_exc}")