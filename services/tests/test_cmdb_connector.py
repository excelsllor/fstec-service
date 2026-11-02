"""RestCMDB-коннектор: auth (none/bearer/basic), пагинация, недоступность → ExternalServiceError."""
import asyncio

import httpx

from security_service.cmdb import RestCMDB
from security_service.resilience import ExternalServiceError

ITEMS = [
    {"host": "srv-app-01", "product": "Log4j", "vendor": "Apache", "version": "2.15.0",
     "cpe": "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", "os": "RED OS 8", "last_seen": "2026-09-01"},
    {"host": "srv-web-02", "product": "OpenSSL", "vendor": "OpenSSL", "version": "1.1.1k",
     "cpe": None, "os": "RED OS 8", "last_seen": "2026-09-01"},
]


def _page_transport(auth_header: str | None = None) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        if auth_header and request.headers.get("Authorization") != auth_header:
            return httpx.Response(401)
        page = int(request.url.params.get("page", "1"))
        total = len(ITEMS)
        if page == 1:
            return httpx.Response(200, json={"items": ITEMS[:1], "page": 1, "total": total})
        return httpx.Response(200, json={"items": ITEMS[1:], "page": 2, "total": total})
    return httpx.MockTransport(handler)


def test_none_auth_paginated():
    cmdb = RestCMDB(endpoint="http://cmdb.local/api/inventory/software",
                    auth_type="none", transport=_page_transport())
    items = asyncio.run(cmdb.find_many("openssl"))
    assert len(items) == 2
    assert items[0].name == "Log4j"
    assert items[0].version == "2.15.0"
    assert items[1].server == "srv-web-02"


def test_bearer_auth():
    cmdb = RestCMDB(endpoint="http://cmdb.local/api/inventory/software",
                    auth_type="bearer", token="sekret", transport=_page_transport("Bearer sekret"))
    items = asyncio.run(cmdb.find_many("x"))
    assert len(items) == 2


def test_basic_auth():
    import base64
    token = "user:pass"
    header = "Basic " + base64.b64encode(token.encode()).decode()
    cmdb = RestCMDB(endpoint="http://cmdb.local/api/inventory/software",
                    auth_type="basic", token=token, transport=_page_transport(header))
    assert len(asyncio.run(cmdb.find_many("x"))) == 2


def test_unavailable_raises_external_error():
    transport = httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("no net")))
    cmdb = RestCMDB(endpoint="http://cmdb.local/api/inventory/software", transport=transport)
    try:
        asyncio.run(cmdb.find_many("openssl"))
        assert False, "ожидали ExternalServiceError"
    except ExternalServiceError:
        pass