"""CMDB Заказчика (Приложение 8): общий протокол инвентаря + REST-коннектор.
RestCMDB ходит в {CMDB_ENDPOINT}?query=..., auth none|bearer|basic, пагинация.
Недоступность CMDB НЕ подменяется фейком: is error → external_errors (ТЗ 4.2)."""
import logging
from dataclasses import dataclass
from typing import Protocol

import httpx

from security_service.http_pool import get_client
from security_service.resilience import retry_async
from shared.config import (CMDB_AUTH_TYPE, CMDB_ENDPOINT, CMDB_PROVIDER,
                           CMDB_TIMEOUT_S, CMDB_TOKEN)

logger = logging.getLogger("fstec.security.cmdb")


@dataclass
class InventoryItem:
    name: str
    vendor: str = ""
    version: str = ""
    category: str = ""
    server: str = ""
    criticality: str = "normal"
    cpe: str = ""
    os: str = ""
    last_seen: str = ""
    installed: bool = True
    assets: int = 1


class InventoryClient(Protocol):
    async def find_many(self, product: str) -> list[InventoryItem]:
        ...


class RestCMDB:
    def __init__(self, endpoint: str = CMDB_ENDPOINT, auth_type: str = CMDB_AUTH_TYPE,
                 token: str = CMDB_TOKEN, timeout_s: float = CMDB_TIMEOUT_S, transport=None):
        self.endpoint = endpoint.rstrip("/")
        self.auth_type = (auth_type or "none").lower()
        self.token = token
        self.timeout = timeout_s
        self.transport = transport

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.auth_type == "bearer" and self.token:
            h["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == "basic" and self.token:
            import base64
            h["Authorization"] = "Basic " + base64.b64encode(self.token.encode()).decode()
        return h

    async def _fetch_page(self, product: str, page: int) -> dict:
        if self.transport is not None:
            kwargs = {"timeout": self.timeout, "transport": self.transport}
            async with httpx.AsyncClient(**kwargs) as client:
                resp = await client.get(self.endpoint, params={"query": product, "page": page},
                                        headers=self._headers())
        else:
            client = get_client("cmdb", timeout=self.timeout)
            resp = await client.get(self.endpoint, params={"query": product, "page": page},
                                    headers=self._headers())
        resp.raise_for_status()
        return resp.json()

    async def _fetch_all(self, product: str) -> list[dict]:
        page, out = 1, []
        while True:
            data = await retry_async(self._fetch_page, product, page)
            items = data.get("items") or []
            out.extend(items)
            total = int(data.get("total", len(items)))
            if not items or page * max(1, len(items)) >= total:
                break
            page += 1
        return out

    async def find_many(self, product: str) -> list[InventoryItem]:
        raw_items = await self._fetch_all(product)
        return [_item_from_rest(r) for r in raw_items]


def _item_from_rest(r: dict) -> InventoryItem:
    return InventoryItem(
        name=str(r.get("product") or r.get("name") or ""),
        vendor=str(r.get("vendor") or ""),
        version=str(r.get("version") or ""),
        server=str(r.get("host") or ""),
        cpe=str(r.get("cpe") or ""),
        os=str(r.get("os") or ""),
        last_seen=str(r.get("last_seen") or ""),
    )


def get_cmdb() -> InventoryClient:
    """Фабрика CMDB: mock (dev) | rest (внешняя CMDB) | glpi (инвентарь ПО GLPI)."""
    if CMDB_PROVIDER in ("glpi", "glpi_db"):
        from shared.config import GLPI_DB_HOST, GLPI_DB_NAME, GLPI_DB_USER, GLPI_URL, IS_PROD
        if GLPI_URL:
            from security_service.glpi import GlpiCMDB
            return GlpiCMDB()
        if GLPI_DB_HOST and GLPI_DB_NAME and GLPI_DB_USER:
            from security_service.glpi_db import GlpiDB
            return GlpiDB()
        if IS_PROD:
            raise RuntimeError("CMDB_PROVIDER=glpi, но GLPI_URL/GLPI_DB_* не заданы (prod: fail-fast)")
        logger.warning("CMDB_PROVIDER=glpi, но GLPI_URL/GLPI_DB_* не заданы - используется mock")
    if CMDB_PROVIDER == "rest":
        return RestCMDB()
    from security_service.cmdb_mock import MockCMDB
    return MockCMDB()