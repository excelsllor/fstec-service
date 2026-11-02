"""SqliteEventBus: доставка, порядок, курсор переживает рестарт."""

import asyncio

from shared.bus import SqliteEventBus


def _run(coro):
    return asyncio.run(coro)


async def _session(db, topic, publish_key=None):
    """Подписка + (опц.) publish; возвращает список доставленных ключей."""
    bus = SqliteEventBus(db_path=db, poll_s=0.05)
    got = []

    async def handler(t, k, payload):
        got.append(k)

    bus.subscribe(topic, handler)
    await bus.start()
    if publish_key is not None:
        await bus.publish(topic, publish_key, {"n": 1})
    for _ in range(200):
        if got or publish_key is None:
            break
        await asyncio.sleep(0.05)
    await bus.stop()
    return got


def test_delivers_in_order(tmp_path):
    got = _run(_session(tmp_path / "a.db", "documents.uploaded"))
    assert got == []

    async def two():
        bus = SqliteEventBus(db_path=tmp_path / "a.db", poll_s=0.05)
        got = []

        async def handler(t, k, payload):
            got.append(k)

        bus.subscribe("documents.uploaded", handler)
        await bus.start()
        await bus.publish("documents.uploaded", "k1", {})
        await bus.publish("documents.uploaded", "k2", {})
        for _ in range(200):
            if len(got) == 2:
                break
            await asyncio.sleep(0.05)
        await bus.stop()
        return got

    assert _run(two()) == ["k1", "k2"]


def test_restart_no_replay(tmp_path):
    db = tmp_path / "b.db"
    first = _run(_session(db, "document.parsed", "old"))
    assert first == ["old"]
    second = _run(_session(db, "document.parsed", "new"))
    assert second == ["new"]                       # старое не переиграли


def test_topic_isolated(tmp_path):
    db = tmp_path / "c.db"
    via_other = _run(_session(db, "document.analyzed", "x"))
    assert via_other == ["x"]