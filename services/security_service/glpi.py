"""GLPI как CMDB Заказчика: инвентарь ПО (Software → SoftwareVersion).

Поддерживаются оба API GLPI 11:
  * v1 (legacy REST, apirest.php): сессия initSession/killSession (Basic или
    user_token), коллекции `Software` и `SoftwareVersion` (версия = поле `name`);
  * v2 (HL API, api.php): OAuth2 password grant, `/Assets/Software` с RSQL-фильтром
    `name=ilike=` и `/Assets/Software/{id}/Version` для версий.

Недоступность GLPI не подменяется фейком: исключение → external_errors (ТЗ 4.2).
Транспорт можно подменить (тесты). Токены кэшируются и обновляются при 401.
"""
import base64
import copy
import logging
import time

import httpx

from security_service.cmdb import InventoryItem
from security_service.http_pool import get_client
from security_service.versioning import match_product
from shared.config import (GLPI_API, GLPI_APP_TOKEN, GLPI_AUTH, GLPI_CLIENT_ID,
                           GLPI_CLIENT_SECRET, GLPI_INVENTORY_CACHE_MAX,
                           GLPI_INVENTORY_CACHE_TTL_S, GLPI_MAX_SOFTWARE,
                           GLPI_MAX_VERSIONS, GLPI_PASSWORD, GLPI_SCOPE,
                           GLPI_TIMEOUT_S, GLPI_URL, GLPI_USER_TOKEN, GLPI_USERNAME)

logger = logging.getLogger("fstec.security.glpi")

_V1_LIST_LIMIT = 50
_V2_PAGE_LIMIT = 50


class GlpiError(RuntimeError):
    pass


class GlpiCMDB:
    def __init__(self, base_url: str = GLPI_URL, api: str = GLPI_API, auth: str = GLPI_AUTH,
                 username: str = GLPI_USERNAME, password: str = GLPI_PASSWORD,
                 user_token: str = GLPI_USER_TOKEN, client_id: str = GLPI_CLIENT_ID,
                 client_secret: str = GLPI_CLIENT_SECRET, scope: str = GLPI_SCOPE,
                 app_token: str = GLPI_APP_TOKEN, timeout_s: float = GLPI_TIMEOUT_S,
                 max_software: int = GLPI_MAX_SOFTWARE, max_versions: int = GLPI_MAX_VERSIONS,
                 transport: httpx.AsyncBaseTransport | None = None):
        if not base_url:
            raise GlpiError("GLPI_URL не задан")
        self.base = base_url.rstrip("/")
        self.api = (api or "v1").lower()
        if self.api not in ("v1", "v2"):
            raise GlpiError(f"Неизвестная версия API GLPI: {api}")
        self.auth = (auth or "basic").lower()
        self.username = username
        self.password = password
        self.user_token = user_token
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope or "api"
        self.app_token = app_token
        self.timeout = timeout_s
        self.max_software = max(1, int(max_software))
        self.max_versions = max(1, int(max_versions))
        self.transport = transport
        self._session_token = ""
        self._access_token = ""
        self._access_expires_at = 0.0
        self._inventory_cache: dict[str, tuple[float, list[InventoryItem]]] = {}

    # ---------------- HTTP ----------------

    async def _do(self, method: str, url: str, *, params=None, headers=None, data=None) -> httpx.Response:
        h = {"Accept": "application/json"}
        if self.app_token:
            h["App-Token"] = self.app_token
        if headers:
            h.update(headers)
        if self.transport is not None:
            async with httpx.AsyncClient(timeout=self.timeout, transport=self.transport) as client:
                return await client.request(method, url, params=params, headers=h, data=data)
        return await get_client("glpi", timeout=self.timeout).request(
            method, url, params=params, headers=h, data=data)

    # ---------------- v1 (legacy REST) ----------------

    async def _init_session(self) -> None:
        if self.auth == "user_token":
            if not self.user_token:
                raise GlpiError("GLPI v1: не задан GLPI_USER_TOKEN")
            headers = {"Authorization": f"user_token {self.user_token}"}
        else:
            if not self.username or not self.password:
                raise GlpiError("GLPI v1: не заданы GLPI_USERNAME/GLPI_PASSWORD")
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers = {"Authorization": f"Basic {token}"}
        resp = await self._do("GET", f"{self.base}/apirest.php/initSession", headers=headers)
        if resp.status_code != 200:
            raise GlpiError(f"GLPI initSession {resp.status_code}: {resp.text[:200]}")
        try:
            self._session_token = resp.json().get("session_token") or ""
        except ValueError as e:
            raise GlpiError(f"GLPI initSession: некорректный JSON: {resp.text[:200]}") from e
        if not self._session_token:
            raise GlpiError(f"GLPI initSession: пустой session_token: {resp.text[:200]}")

    async def _v1_list(self, path: str, params: dict) -> list[dict]:
        if not self._session_token:
            await self._init_session()
        resp = await self._do("GET", f"{self.base}/apirest.php/{path}",
                              params=params, headers={"Session-Token": self._session_token})
        if resp.status_code == 401:
            await self._init_session()
            resp = await self._do("GET", f"{self.base}/apirest.php/{path}",
                                  params=params, headers={"Session-Token": self._session_token})
        if resp.status_code not in (200, 206):
            raise GlpiError(f"GLPI {path} {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("data", "items"):
                if isinstance(data.get(key), list):
                    return data[key]
        return []

    async def _find_v1(self, product: str) -> list[InventoryItem]:
        query = product.split()[0] if product.split() else product
        rows = await self._v1_list("Software/", {
            "searchText[name]": query,
            "expand_dropdowns": "true",
            "range": f"0-{_V1_LIST_LIMIT - 1}",
        })
        out: list[InventoryItem] = []
        for sw in rows[: self.max_software]:
            if not isinstance(sw, dict):
                continue
            name = str(sw.get("name") or "")
            if not match_product(name, product):
                continue
            vendor = str(sw.get("manufacturers_id") or "")
            category = str(sw.get("softwarecategories_id") or "")
            sw_id = sw.get("id")
            if sw_id is None:
                continue
            versions = await self._v1_list(f"Software/{sw_id}/SoftwareVersion", {
                "expand_dropdowns": "true",
                "range": f"0-{self.max_versions - 1}",
            })
            for v in versions[: self.max_versions]:
                if isinstance(v, dict):
                    out.append(InventoryItem(name=name, vendor=vendor, category=category,
                                             version=str(v.get("name") or "")))
        return out

    # ---------------- v2 (HL API, OAuth2) ----------------

    async def _oauth_token(self, force: bool = False) -> None:
        if (not force and self._access_token
                and time.time() < self._access_expires_at - 30):
            return
        if not self.client_id or not self.client_secret:
            raise GlpiError("GLPI v2: не заданы GLPI_CLIENT_ID/GLPI_CLIENT_SECRET")
        if not self.username or not self.password:
            raise GlpiError("GLPI v2: не заданы GLPI_USERNAME/GLPI_PASSWORD")
        resp = await self._do("POST", f"{self.base}/api.php/token", data={
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password,
            "scope": self.scope,
        })
        if resp.status_code != 200:
            raise GlpiError(f"GLPI token {resp.status_code}: {resp.text[:200]}")
        try:
            js = resp.json()
        except ValueError as e:
            raise GlpiError(f"GLPI token: некорректный JSON: {resp.text[:200]}") from e
        self._access_token = js.get("access_token") or ""
        if not self._access_token:
            raise GlpiError(f"GLPI token: пустой access_token: {resp.text[:200]}")
        self._access_expires_at = time.time() + float(js.get("expires_in") or 3600)

    async def _v2_list(self, path: str, params: dict) -> list[dict]:
        await self._oauth_token()
        headers = {"Authorization": f"Bearer {self._access_token}"}
        resp = await self._do("GET", f"{self.base}/api.php/{path}", params=params, headers=headers)
        if resp.status_code == 401:
            await self._oauth_token(force=True)
            headers = {"Authorization": f"Bearer {self._access_token}"}
            resp = await self._do("GET", f"{self.base}/api.php/{path}", params=params, headers=headers)
        if resp.status_code not in (200, 206):
            raise GlpiError(f"GLPI {path} {resp.status_code}: {resp.text[:200]}")
        data = resp.json()
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("items", "data", "results"):
                if isinstance(data.get(key), list):
                    return data[key]
        return []

    async def _find_v2(self, product: str) -> list[InventoryItem]:
        query = product.split()[0] if product.split() else product
        rows = await self._v2_list("v2/Assets/Software", {
            "filter": f"name=ilike={query}",
            "limit": _V2_PAGE_LIMIT,
        })
        out: list[InventoryItem] = []
        for sw in rows[: self.max_software]:
            if not isinstance(sw, dict):
                continue
            name = str(sw.get("name") or "")
            if not match_product(name, product):
                continue
            manufacturer = sw.get("manufacturer")
            vendor = str(manufacturer.get("name") or "") if isinstance(manufacturer, dict) else ""
            category = sw.get("category")
            cat = str(category.get("name") or "") if isinstance(category, dict) else ""
            sw_id = sw.get("id")
            if sw_id is None:
                continue
            versions = await self._v2_list(f"v2/Assets/Software/{sw_id}/Version",
                                           {"limit": self.max_versions})
            for v in versions[: self.max_versions]:
                if isinstance(v, dict):
                    out.append(InventoryItem(name=name, vendor=vendor, category=cat,
                                             version=str(v.get("name") or "")))
        return out

    # ---------------- InventoryClient ----------------

    async def find_many(self, product: str) -> list[InventoryItem]:
        if not product or not product.strip():
            return []
        product = product.strip()
        key = product.lower()
        now = time.monotonic()
        cached = self._inventory_cache.get(key)
        if cached and GLPI_INVENTORY_CACHE_TTL_S > 0 and now - cached[0] < GLPI_INVENTORY_CACHE_TTL_S:
            return copy.deepcopy(cached[1])
        if self.api == "v2":
            result = await self._find_v2(product)
        else:
            result = await self._find_v1(product)
        if GLPI_INVENTORY_CACHE_TTL_S > 0:
            self._inventory_cache[key] = (now, copy.deepcopy(result))
            while len(self._inventory_cache) > GLPI_INVENTORY_CACHE_MAX:
                self._inventory_cache.pop(next(iter(self._inventory_cache)))
        return result

    async def close(self) -> None:
        if self._session_token:
            try:
                await self._do("GET", f"{self.base}/apirest.php/killSession",
                               headers={"Session-Token": self._session_token})
            except Exception:  # noqa: BLE001 — закрытие не должно ронять shutdown
                logger.warning("GLPI killSession failed", exc_info=True)
            self._session_token = ""
