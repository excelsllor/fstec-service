"""GlpiCMDB: v1 (initSession + Software/SoftwareVersion) и v2 (OAuth2 + Assets/Software)."""
import asyncio

import httpx
import pytest

from security_service.glpi import GlpiCMDB, GlpiError


def _run(coro):
    return asyncio.run(coro)


def test_v1_find_many_and_session_reuse():
    calls = {"init": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/apirest.php/initSession"):
            calls["init"] += 1
            assert req.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"session_token": "tok1"})
        if p.endswith("/apirest.php/Software/"):
            assert req.headers["session-token"] == "tok1"
            assert req.url.params["searchText[name]"] == "Log4j"
            return httpx.Response(200, json=[
                {"id": 7, "name": "Apache Log4j", "manufacturers_id": "Apache"},
            ])
        if p.endswith("/apirest.php/Software/7/SoftwareVersion"):
            return httpx.Response(206, json=[{"id": 1, "name": "2.15.0"}, {"id": 2, "name": "2.17.0"}])
        return httpx.Response(404)

    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v1", auth="basic",
                    username="u", password="p", transport=httpx.MockTransport(handler))
    items = _run(cmdb.find_many("Log4j"))
    assert [i.version for i in items] == ["2.15.0", "2.17.0"]
    assert items[0].name == "Apache Log4j" and items[0].vendor == "Apache"
    assert calls["init"] == 1


def test_find_many_uses_inventory_cache():
    calls = {"software": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/apirest.php/initSession"):
            return httpx.Response(200, json={"session_token": "tok"})
        if p.endswith("/apirest.php/Software/"):
            calls["software"] += 1
            return httpx.Response(200, json=[{"id": 1, "name": "Samba"}])
        if p.endswith("/apirest.php/Software/1/SoftwareVersion"):
            return httpx.Response(200, json=[{"name": "4.23.0"}])
        return httpx.Response(404)

    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v1", auth="basic",
                    username="u", password="p", transport=httpx.MockTransport(handler))
    assert _run(cmdb.find_many("Samba"))
    assert _run(cmdb.find_many("Samba"))
    assert calls["software"] == 1


def test_v1_reauth_on_401():
    state = {"software_calls": 0, "init": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/apirest.php/initSession"):
            state["init"] += 1
            return httpx.Response(200, json={"session_token": f"tok{state['init']}"})
        if p.endswith("/apirest.php/Software/"):
            state["software_calls"] += 1
            if state["software_calls"] == 1:
                assert req.headers["session-token"] == "tok1"
                return httpx.Response(401, json=["ERROR", "SESSION_TOKEN_INVALID"])
            assert req.headers["session-token"] == "tok2"
            return httpx.Response(200, json=[{"id": 1, "name": "Samba"}])
        if p.endswith("/apirest.php/Software/1/SoftwareVersion"):
            return httpx.Response(200, json=[{"name": "4.19.0"}])
        return httpx.Response(404)

    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v1", auth="user_token",
                    user_token="secret-token", transport=httpx.MockTransport(handler))
    items = _run(cmdb.find_many("Samba"))
    assert state["init"] == 2
    assert items and items[0].version == "4.19.0"


def test_v2_oauth_and_versions():
    tokens = {"calls": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p.endswith("/api.php/token"):
            tokens["calls"] += 1
            body = req.content.decode()
            assert "grant_type=password" in body and "client_id=cid" in body
            return httpx.Response(200, json={"access_token": "acc1", "expires_in": 3600,
                                             "token_type": "Bearer"})
        if p.endswith("/api.php/v2/Assets/Software"):
            assert req.headers["authorization"] == "Bearer acc1"
            assert req.url.params["filter"] == "name=ilike=OpenSSL"
            return httpx.Response(200, json={"items": [
                {"id": 3, "name": "OpenSSL", "manufacturer": {"id": 1, "name": "OpenSSL Project"}},
            ]})
        if p.endswith("/api.php/v2/Assets/Software/3/Version"):
            return httpx.Response(200, json=[{"id": 10, "name": "1.1.1k"}])
        return httpx.Response(404)

    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v2", username="u", password="p",
                    client_id="cid", client_secret="sec", transport=httpx.MockTransport(handler))
    items = _run(cmdb.find_many("OpenSSL"))
    assert len(items) == 1
    assert items[0].version == "1.1.1k" and items[0].vendor == "OpenSSL Project"
    _run(cmdb.find_many("OpenSSL"))
    assert tokens["calls"] == 1


def test_v1_error_raises():
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/apirest.php/initSession"):
            return httpx.Response(200, json={"session_token": "t"})
        return httpx.Response(500, text="boom")

    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v1", auth="basic",
                    username="u", password="p", transport=httpx.MockTransport(handler))
    with pytest.raises(GlpiError):
        _run(cmdb.find_many("x"))


def test_missing_credentials_raise():
    cmdb = GlpiCMDB(base_url="https://glpi.example", api="v1", auth="basic", transport=httpx.MockTransport(
        lambda req: httpx.Response(200, json={})))
    with pytest.raises(GlpiError):
        _run(cmdb.find_many("x"))
    with pytest.raises(GlpiError):
        GlpiCMDB(base_url="")
