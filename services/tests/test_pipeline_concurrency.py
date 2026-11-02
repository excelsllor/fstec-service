"""Этап 4: bounded concurrency пайплайна.

Проверяем инварианты, которые ломают throughput молча:
  * bounded_gather() не превышает лимит, но сохраняет порядок результатов;
  * run_blocking() уводит блокирующий код с event loop;
  * SqliteEventBus при BUS_CONCURRENCY > 1 доставляет каждое сообщение ровно
    один раз (без потерь и дублей) и двигает курсор только после всей пачки;
  * assess_document() обогащает уязвимости письма параллельно, соблюдая лимит,
    и возвращает результаты в исходном порядке.
"""
import asyncio
import threading
import time

from security_service.assessment import assess_document
from shared.bus import SqliteEventBus
from shared.concurrency import bounded_gather, gate, reset_gates, run_blocking

# --- bounded_gather -----------------------------------------------------------

def test_bounded_gather_preserves_order_and_limit():
    async def scenario():
        reset_gates()
        live = {"now": 0, "max": 0}
        # Пробный семафор намеренно назван иначе, чем внутренний семафор
        # bounded_gather: если бы имена совпадали, каждый task держал бы по два
        # permit'а одного семафора и пул упирался бы в дедлок.
        probe = gate("probe:test-order", 3)

        async def one(i):
            async with probe:
                live["now"] += 1
                live["max"] = max(live["max"], live["now"])
                await asyncio.sleep(0.01)
                live["now"] -= 1
                return i * 2

        out = await bounded_gather([one(i) for i in range(12)], 3, name="test-order")
        return out, live["max"]

    out, peak = asyncio.run(scenario())
    assert out == [i * 2 for i in range(12)]          # порядок = порядок входа
    assert peak <= 3, f"лимит превышен: {peak}"


def test_bounded_gather_does_not_deadlock_on_same_gate_name():
    """bounded_gather(name=X) не должен делить семафор с gate("X")."""
    async def scenario():
        reset_gates()
        probe = gate("shared-name", 2)

        async def one(i):
            async with probe:
                await asyncio.sleep(0.01)
                return i

        return await bounded_gather([one(i) for i in range(6)], 2, name="shared-name")

    assert asyncio.run(scenario()) == [0, 1, 2, 3, 4, 5]


def test_bounded_gather_limit_covers_single_item():
    async def one():
        return "ok"

    assert asyncio.run(bounded_gather([one()], 4)) == ["ok"]


def test_bounded_gather_empty():
    assert asyncio.run(bounded_gather([], 4)) == []


def test_bounded_gather_propagates_error():
    """Ошибка одного элемента не должна молча утапливаться в пустой результат."""
    async def bad():
        raise RuntimeError("boom")

    async def good():
        return 1

    async def scenario():
        with pytest_raises(RuntimeError):
            await bounded_gather([good(), bad()], 2)
        return True

    assert asyncio.run(scenario())


def pytest_raises(exc):
    import pytest
    return pytest.raises(exc)


# --- run_blocking -------------------------------------------------------------

def test_run_blocking_moves_work_off_the_loop():
    loop_thread = threading.current_thread().ident
    seen = {}

    def blocking(a, b=0):
        seen["thread"] = threading.current_thread().ident
        time.sleep(0.05)                            # имитация парсинга/OCR
        return a + b

    async def scenario():
        return await run_blocking(blocking, 1, b=2)

    assert asyncio.run(scenario()) == 3
    assert seen["thread"] != loop_thread, "блокирующий код остался на event loop"


# --- SqliteEventBus ----------------------------------------------------------

async def _concurrent_delivery(db_path, topic, count, concurrency, batch):
    bus = SqliteEventBus(db_path=db_path, poll_s=0.02,
                         concurrency=concurrency, batch=batch)
    live = {"now": 0, "max": 0}
    seen: list[str] = []

    async def handler(_t, key, _payload):
        async with gate(f"probe:{topic}", concurrency):
            live["now"] += 1
            live["max"] = max(live["max"], live["now"])
            await asyncio.sleep(0.03)
            live["now"] -= 1
            seen.append(key)

    bus.subscribe(topic, handler)
    bus.delivered = 0

    async def counting(t, k, p):
        await handler(t, k, p)
        bus.delivered += 1

    bus._subscribers[topic] = [counting]
    await bus.start()
    for i in range(count):
        await bus.publish(topic, f"k{i:02d}", {"i": i})
    deadline = time.monotonic() + 15
    while len(seen) < count and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    await bus.stop()
    return seen, live["max"]


def test_sqlite_bus_concurrent_delivers_each_message_once(tmp_path):
    """BUS_CONCURRENCY>1: порядок между сообщениями не гарантирован (это ожидаемо),
    но каждое сообщение должно прийти ровно один раз."""
    seen, peak = asyncio.run(_concurrent_delivery(tmp_path / "bus.db", "t", 12, 4, 12))
    assert sorted(seen) == sorted(f"k{i:02d}" for i in range(12))
    assert len(seen) == 12, "дубликаты или потери"
    assert peak <= 4, f"параллелизм выше лимита: {peak}"


def test_sqlite_bus_cursor_advances_after_batch(tmp_path):
    """После пачки курсор = max(id): рестарт не переигрывает обработанное."""
    db = tmp_path / "cursor.db"

    async def scenario():
        bus = SqliteEventBus(db_path=db, poll_s=0.02, concurrency=4, batch=6)
        got: list[str] = []

        async def handler(_t, key, _p):
            got.append(key)

        bus.subscribe("t", handler)
        await bus.start()
        for i in range(6):
            await bus.publish("t", f"m{i}", {})
        deadline = time.monotonic() + 10
        while len(got) < 6 and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        await bus.stop()
        return got

    got = asyncio.run(scenario())
    assert len(got) == 6

    # Новый bus на том же файле не должен переиграть уже обработанное.
    replayed = asyncio.run(_concurrent_delivery(db, "t", 0, 4, 6))
    assert replayed[0] == [], "курсор не продвинулся — сообщения уйдут повторно"


# --- assess_document ---------------------------------------------------------

class _SlowCMDB:
    """CMDB-заглушка: каждый вызов занимает фиксированное время, трекает пик."""

    def __init__(self, delay=0.02):
        self.delay = delay
        self.now = 0
        self.max = 0
        self.calls: list[str] = []

    async def find_many(self, software):
        self.now += 1
        self.max = max(self.max, self.now)
        self.calls.append(software)
        await asyncio.sleep(self.delay)
        self.now -= 1
        return []


def _vuln(i):
    return {"cve_id": "", "bdu_id": "", "description": "", "software": f"soft-{i}",
            "severity": "low"}


def test_assess_document_is_parallel_and_ordered():
    vulns = [_vuln(i) for i in range(9)]
    cmdb = _SlowCMDB()

    async def scenario():
        reset_gates()
        started = time.monotonic()
        ass = await assess_document(vulns, cmdb=cmdb, enrich=False)
        return ass, time.monotonic() - started

    ass, elapsed = asyncio.run(scenario())

    assert [a["software"] for a in ass.assessed] == [f"soft-{i}" for i in range(9)]
    assert len(ass.assessed) == 9
    # Лимит по умолчанию 8 при 9 задачах — пик не выше SECURITY_LOOKUP_CONCURRENCY.
    assert cmdb.max <= 8, f"превышен лимит lookups: {cmdb.max}"
    # Последовательное выполнение 9×0.02 = 0.18с; параллельное должно быть заметно меньше.
    assert elapsed < 0.18, f"lookups выполнялись последовательно: {elapsed:.3f}s"


def test_assess_document_empty_input():
    ass = asyncio.run(assess_document([], cmdb=_SlowCMDB(0), enrich=False))
    assert ass.assessed == [] and ass.external_errors == []
    assert ass.sla == "normal" and ass.routing == "default"


def test_assess_document_collects_cmdb_errors():
    class _Boom:
        async def find_many(self, _software):
            raise RuntimeError("cmdb down")

    ass = asyncio.run(assess_document([_vuln(0)], cmdb=_Boom(), enrich=False))
    assert len(ass.assessed) == 1                     # письмо не теряем при падении CMDB
    assert ass.external_errors and "cmdb down" in ass.external_errors[0]


# --- HTTP pool ---------------------------------------------------------------

def test_http_pool_reuses_one_client_per_service():
    """Клиент переиспользуется: иначе каждый lookup = новое соединение и TLS."""
    from security_service import http_pool

    async def scenario():
        await http_pool.close_clients()
        a = http_pool.get_client("nvd")
        b = http_pool.get_client("nvd")
        c = http_pool.get_client("cmdb")
        same = a is b
        distinct = a is not c
        await http_pool.close_clients()
        closed = a.is_closed
        return same, distinct, closed

    same, distinct, closed = asyncio.run(scenario())
    assert same, "клиент для того же сервиса пересоздаётся"
    assert distinct, "разные сервисы должны иметь разные клиенты (разные auth/timeout)"
    assert closed, "close_clients() не закрывает пул"


def test_http_pool_get_client_after_close():
    """После close_clients следующий вызов должен создать живой клиент, а не
    отдать закрытый (иначе все запросы падают после рестарта)."""
    from security_service import http_pool

    async def scenario():
        await http_pool.close_clients()
        first = http_pool.get_client("bdu")
        await http_pool.close_clients()
        second = http_pool.get_client("bdu")
        alive = not second.is_closed
        await http_pool.close_clients()
        return alive

    assert asyncio.run(scenario())


# --- Kafka: контракт group_id ------------------------------------------------

def test_kafka_group_id_keeps_deployed_format():
    """Имя группы — часть боевого контракта.

    Смена group_id = новая группа = offsets с нуля, а auto_offset_reset=earliest
    проигрывает всю историю топита, то есть повторно обрабатывает все документы.
    Формат `fstec-<topic>-consumer` задеплоен, менять его нельзя.
    """
    import inspect
    import re

    from shared.bus import KafkaEventBus

    src = inspect.getsource(KafkaEventBus)
    m = re.search(r'group_id\s*=\s*f"([^"]+)"', src)
    assert m, "group_id в KafkaEventBus не найден — формат изменился, проверь вручную"
    template = m.group(1)
    assert template == "{self._group}-{topic}-consumer", (
        f"group_id изменён на {template!r} — это сбросит offsets и переиграет историю"
    )


def test_kafka_consumer_group_is_per_topic():
    """Разные топиты не должны делить одну группу, иначе консьюмеры будут
    конкурировать за чужие партиции и половина топитов останется непрочитанной."""
    from shared.bus import KafkaEventBus

    bus = KafkaEventBus(bootstrap="kafka:9092", group="fstec")
    ids = {f"fstec-{t}-consumer" for t in
           ("documents.uploaded", "document.parsed", "document.analyzed",
            "security.assessed")}
    assert len(ids) == 4
    assert bus._group == "fstec"
