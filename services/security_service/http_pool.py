"""Общий пул HTTP-соединений для внешних источников (этап 4).

Раньше каждый запрос создавал свой `httpx.AsyncClient`, то есть на каждый вызов
NVD/BDU/CMDB приходились новое TCP-соединение и новый TLS-хендшейк. После
распараллеливания обработки письма (до `SECURITY_LOOKUP_CONCURRENCY` запросов
одновременно) это давало всплеск fd, лишние рукопожатия и заметную задержку на
TLS. Здесь держим один долгоживущий клиент на сервис.

Клиент на сервис, а не один общий: у NVD/BDU/CMDB разные заголовки авторизации
и таймауты, которые задаются при создании `AsyncClient`.

Когда передан `transport` (тесты, оффлайн-разбор), используется клиент на один
вызов: инъектированный transport нельзя переиспользовать между сессиями.
"""
import logging

import httpx

from shared.config import SECURITY_POOL_MAX_CONNECTIONS

logger = logging.getLogger(__name__)

_clients: dict[str, httpx.AsyncClient] = {}


def get_client(name: str, *, timeout: float = 10.0, connect: float = 5.0,
               follow_redirects: bool = False) -> httpx.AsyncClient:
    """Вернуть (или создать) долгоживущий клиент сервиса `name`."""
    client = _clients.get(name)
    if client is not None and not client.is_closed:
        return client
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(timeout, connect=connect),
        limits=httpx.Limits(max_connections=SECURITY_POOL_MAX_CONNECTIONS,
                            max_keepalive_connections=SECURITY_POOL_MAX_CONNECTIONS),
        follow_redirects=follow_redirects,
    )
    _clients[name] = client
    logger.debug("HTTP pool created: %s", name)
    return client


async def close_clients() -> None:
    """Закрыть все pooled-клиенты (вызывается при остановке воркера)."""
    for name, client in list(_clients.items()):
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 — закрытие не должно ронять shutdown
            logger.warning("failed to close HTTP pool %s", name, exc_info=True)
    _clients.clear()
