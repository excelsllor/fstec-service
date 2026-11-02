import asyncio

from security_service.glpi_db import GlpiDB, _matches_product


class _Cursor:
    def __init__(self, calls):
        self.calls = calls
        self.rows = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, sql, params):
        self.calls.append((sql, params))
        if "FROM glpi_software" in sql and "computers_softwareversions" not in sql:
            self.rows = [
                {"id": 1, "name": "trueconf"},
                {"id": 2, "name": "trueconf server"},
            ]
        else:
            self.rows = [
                {"software_name": "trueconf server", "version": "5.5.0",
                 "assets": 4, "last_seen": "2026-10-28"},
                {"software_name": "trueconf server", "version": "5.5.1",
                 "assets": 1, "last_seen": "2026-10-27"},
            ]

    def fetchall(self):
        return self.rows


class _Connection:
    def __init__(self, calls):
        self.calls = calls

    def cursor(self):
        return _Cursor(self.calls)

    def close(self):
        return None


def test_product_matching_does_not_mix_client_and_server():
    assert _matches_product("trueconf server", "TrueConf Server")
    assert not _matches_product("trueconf", "TrueConf Server")


def test_glpi_db_returns_installed_versions(monkeypatch):
    db = GlpiDB(host="db", database="glpi", user="reader", password="secret")
    calls = []
    monkeypatch.setattr(db, "_connect", lambda: _Connection(calls))
    items = asyncio.run(db.find_many("TrueConf Server"))
    assert [item.version for item in items] == ["5.5.0", "5.5.1"]
    assert items[0].assets == 4
    assert items[0].installed is True
    assert any("%trueconf%" in str(params).lower() for _, params in calls)
