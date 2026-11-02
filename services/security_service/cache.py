"""Кэш внешних БД уязвимостей (NVD/BDU): Redis с TTL (по умолчанию 24 ч) и прозрачный
fallback на in-memory TTL-кэш, когда Redis недоступен (dev/CI) или не сконфигурирован.

Негативный кэш: `set(key, None)` (внешняя БД ответила «такого ID нет») обязан отличаться
от промаха, иначе каждый следующий запрос снова уходит в сеть. Для этого значение None
хранится как маркер `EMPTY`, а `get` возвращает его вместо None."""
import json
import logging
import time
from typing import Any

from shared.config import REDIS_URL, SECURITY_CACHE_TTL_S

logger = logging.getLogger("fstec.security.cache")

_EMPTY_FLAG = "__fstec_empty__"


class _Empty:
    """Маркер негативного кэша: ID обработан, но внешняя БД не вернула данных."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - отладка
        return "<cache-empty>"


EMPTY = _Empty()


def _pack(value: Any) -> Any:
    return {_EMPTY_FLAG: True} if value is None else value


def _unpack(raw: Any) -> Any:
    if isinstance(raw, dict) and raw.get(_EMPTY_FLAG) is True:
        return EMPTY
    return raw



class Cache:
    async def get(self, key: str) -> Any | None:  # pragma: no cover - interface
        raise NotImplementedError

    async def set(self, key: str, value: Any, ttl_s: int = SECURITY_CACHE_TTL_S) -> None:  # pragma: no cover
        raise NotImplementedError

    async def close(self) -> None:  # pragma: no cover
        raise NotImplementedError


class MemoryCache(Cache):
    """In-memory TTL-кэш (dev/CI, fallback при недоступном Redis)."""

    def __init__(self):
        self._data: dict[str, tuple[Any, float]] = {}

    async def get(self, key: str) -> Any | None:
        item = self._data.get(key)
        if not item:
            return None
        value, deadline = item
        if deadline < time.monotonic():
            self._data.pop(key, None)
            return None
        return _unpack(value)

    async def set(self, key: str, value: Any, ttl_s: int = SECURITY_CACHE_TTL_S) -> None:
        self._data[key] = (_pack(value), time.monotonic() + ttl_s)

    async def close(self) -> None:
        self._data.clear()


_cache: Cache | None = None


def get_cache() -> Cache:
    """Единый кэш NVD/BDU (Redis → memory-fallback)."""
    global _cache
    if _cache is None:
        _cache = RedisCache()
    return _cache


class RedisCache(Cache):

    def __init__(self, url: str = REDIS_URL, fallback: Cache | None = None):
        self._url = url
        self._fallback = fallback or MemoryCache()
        self._redis = None

    async def _client(self):
        if self._redis is None:
            from redis.asyncio import Redis
            # fail-fast: Redis локальный (docker), не должен тормозить обработку письма
            self._redis = Redis.from_url(self._url, socket_timeout=1.0, socket_connect_timeout=1.0)
        return self._redis

    async def get(self, key: str) -> Any | None:
        try:
            raw = await (await self._client()).get(key)
            return _unpack(json.loads(raw)) if raw is not None else None
        except Exception as exc:  # noqa: BLE001
            logger.warning("redis get failed (%s): %s; using memory cache", key, exc)
            return await self._fallback.get(key)

    async def set(self, key: str, value: Any, ttl_s: int = SECURITY_CACHE_TTL_S) -> None:
        try:
            await (await self._client()).set(key, json.dumps(_pack(value), ensure_ascii=False, default=str), ex=ttl_s)
        except Exception as exc:  # noqa: BLE001
            logger.warning("redis set failed (%s): %s; using memory cache", key, exc)
            await self._fallback.set(key, value, ttl_s)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            except Exception:  # noqa: BLE001
                pass
        await self._fallback.close()