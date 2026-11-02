"""Событийная шина: Kafka (prod), SQLite (локальный мульти-процесс) или in-memory (тесты).

Интерфейс:
  bus.start() / bus.stop()
  await bus.publish(topic, key, payload: dict)   # payload keyed as str
  bus.subscribe(topic, handler)                   # handler(topic, key, payload)
"""
import asyncio
import json
import logging
import sqlite3
import ssl
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Awaitable, Callable

from shared.config import (BUS_BATCH, BUS_CONCURRENCY, BUS_POLL_S, DB_PATH,
                            EVENT_BUS, KAFKA_BOOTSTRAP, KAFKA_CONSUMER_GROUP,
                            KAFKA_SASL_MECHANISM, KAFKA_SASL_PASSWORD,
                            KAFKA_SASL_USERNAME, KAFKA_SECURITY_PROTOCOL,
                            KAFKA_SSL_CA_FILE)
from shared.concurrency import gate

logger = logging.getLogger(__name__)

Handler = Callable[[str, str, dict], Awaitable[None]]

TOPICS = [
    "documents.uploaded",
    "document.parsed",
    "document.analyzed",
    "security.assessed",
    "report.ready",
    "reply.generated",
    "audit.events",
    "documents.failed",   # DLQ при исчерпании ретраев внешних сервисов (ТЗ 4.2)
]


class EventBus(ABC):
    @abstractmethod
    async def start(self): ...

    @abstractmethod
    async def stop(self): ...

    @abstractmethod
    async def publish(self, topic: str, key: str, payload: dict) -> None: ...

    @abstractmethod
    def subscribe(self, topic: str, handler: Handler) -> None: ...


class MemoryEventBus(EventBus):
    """Процессная шина: детерминирована (publish ждёт обработчиков). Для dev/CI."""

    def __init__(self):
        self._subscribers: dict[str, list[Handler]] = {}

    async def start(self):
        pass

    async def stop(self):
        pass

    def subscribe(self, topic: str, handler: Handler) -> None:
        subs = self._subscribers.setdefault(topic, [])
        if handler not in subs:
            subs.append(handler)

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        for handler in list(self._subscribers.get(topic, [])):
            try:
                await handler(topic, key, payload)
            except Exception:
                logger.exception("Memory bus handler failed on %s key=%s", topic, key)


class SqliteEventBus(EventBus):
    """Межпроцессная шина на SQLite (локальный запуск без Kafka/Redis).

    Сообщения пишутся в bus_message; каждый топик имеет курсор (bus_cursor),
    который подписчик продвигает после обработки. Курсор создаётся при первой
    подписке как INSERT OR IGNORE на максимальный id → рестарт воркера не
    переигрывает уже обработанное, а сообщения, пришедшие пока воркер был
    остановлен, доставляются после его перезапуска.

    Этап 4: BUS_CONCURRENCY > 1 обрабатывает сообщения пачки параллельно, но
    курсор по-прежнему сдвигается только после завершения ВСЕЙ пачки — при
    перезапуске непрогнанное сообщение не теряется. Внутри одного сообщения
    подписчики вызываются строго по порядку.
    """

    _SCHEMA = [
        """CREATE TABLE IF NOT EXISTS bus_message (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            topic TEXT NOT NULL,
            msg_key TEXT,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS bus_cursor (
            topic TEXT PRIMARY KEY,
            last_id INTEGER NOT NULL DEFAULT 0)""",
    ]

    def __init__(self, db_path: str | Path | None = None, poll_s: float | None = None,
                 concurrency: int | None = None, batch: int | None = None):
        self._db_path = str(db_path or DB_PATH)
        self._poll_s = poll_s if poll_s is not None else BUS_POLL_S
        self._concurrency = max(1, concurrency if concurrency is not None else BUS_CONCURRENCY)
        self._batch = max(1, batch if batch is not None else BUS_BATCH)
        self._subscribers: dict[str, list[Handler]] = {}
        self._tasks: list[asyncio.Task] = []
        self._conn: sqlite3.Connection | None = None
        self._loop: asyncio.AbstractEventLoop | None = None

    def _ensure_conn(self) -> sqlite3.Connection:
        if self._conn is None:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            for stmt in self._SCHEMA:
                conn.execute(stmt)
            conn.commit()
            self._conn = conn
        return self._conn

    def _init_cursor(self, topic: str) -> None:
        conn = self._ensure_conn()
        row = conn.execute("SELECT MAX(id) FROM bus_message WHERE topic=?", (topic,)).fetchone()
        max_id = row[0] if row and row[0] is not None else 0
        conn.execute("INSERT OR IGNORE INTO bus_cursor (topic, last_id) VALUES (?, ?)",
                     (topic, max_id))
        conn.commit()

    async def start(self):
        self._loop = asyncio.get_event_loop()
        self._ensure_conn()
        for topic in list(self._subscribers):
            self._tasks.append(self._loop.create_task(self._poll(topic)))

    async def stop(self):
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        if self._conn is not None:
            self._conn.close()
            self._conn = None
        self._loop = None

    def subscribe(self, topic: str, handler: Handler) -> None:
        subs = self._subscribers.setdefault(topic, [])
        if handler not in subs:
            subs.append(handler)
        self._init_cursor(topic)

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        if self._conn is None:
            await self.start()
        encoded = json.dumps(payload, ensure_ascii=False, default=str)
        now = datetime_now_iso()
        await self._loop.run_in_executor(None, self._insert, topic, key, encoded, now)

    def _insert(self, topic: str, key: str, encoded: str, now: str) -> None:
        conn = self._ensure_conn()
        conn.execute(
            "INSERT INTO bus_message (topic, msg_key, payload, created_at) VALUES (?, ?, ?, ?)",
            (topic, key, encoded, now))
        conn.commit()

    async def _poll(self, topic: str, batch: int | None = None) -> None:
        while True:
            try:
                await self._deliver(topic, batch or self._batch)
            except Exception:
                logger.exception("sqlite bus poll failed topic=%s", topic)
            await asyncio.sleep(self._poll_s)

    async def _dispatch(self, sem: asyncio.Semaphore | None, topic: str,
                        key: str, data: dict) -> None:
        """Одно сообщение: подписчики строго последовательно, но разные сообщения
        могут идти одновременно (ограничение — семафор sem)."""
        handlers = list(self._subscribers.get(topic, []))
        if sem is None:
            for handler in handlers:
                try:
                    await handler(topic, key, data)
                except Exception:
                    logger.exception("sqlite bus handler failed on %s key=%s", topic, key)
            return
        async with sem:
            for handler in handlers:
                try:
                    await handler(topic, key, data)
                except Exception:
                    logger.exception("sqlite bus handler failed on %s key=%s", topic, key)

    async def _deliver(self, topic: str, batch: int) -> None:
        def _fetch():
            conn = self._ensure_conn()
            cur = conn.execute("SELECT last_id FROM bus_cursor WHERE topic=?", (topic,)).fetchone()
            last = cur[0] if cur else 0
            rows = conn.execute(
                "SELECT id, msg_key, payload FROM bus_message WHERE topic=? AND id>? "
                "ORDER BY id LIMIT ?", (topic, last, batch)).fetchall()
            return last, [(r[0], r[1], r[2]) for r in rows]

        def _advance(max_id: int) -> None:
            conn = self._ensure_conn()
            conn.execute("INSERT INTO bus_cursor (topic, last_id) VALUES (?, ?) "
                         "ON CONFLICT(topic) DO UPDATE SET last_id = excluded.last_id",
                         (topic, max_id))
            conn.commit()

        last, rows = await self._loop.run_in_executor(None, _fetch)
        if not rows:
            return
        max_id = last
        decoded = []
        for rid, key, payload in rows:
            max_id = max(max_id, rid)
            try:
                data = json.loads(payload) if payload else {}
            except Exception:
                data = {}
            decoded.append((key or "", data))

        # Курсор двигаем только после того, как вся пачка доставлена: иначе
        # перезапуск воркера потерял бы сообщения, которые уже вычитали,
        # но не успели обработать.
        if self._concurrency <= 1:
            for key, data in decoded:
                await self._dispatch(None, topic, key, data)
        else:
            sem = gate(f"bus:{topic}", self._concurrency)
            await asyncio.gather(*(self._dispatch(sem, topic, key, data)
                                   for key, data in decoded))
        await self._loop.run_in_executor(None, _advance, max_id)


def datetime_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def kafka_security_kwargs() -> dict:
    protocol = KAFKA_SECURITY_PROTOCOL
    if protocol == "PLAINTEXT":
        return {}
    kwargs: dict = {"security_protocol": protocol}
    if "SASL" in protocol:
        kwargs["sasl_mechanism"] = KAFKA_SASL_MECHANISM
        kwargs["sasl_plain_username"] = KAFKA_SASL_USERNAME
        kwargs["sasl_plain_password"] = KAFKA_SASL_PASSWORD
    if "SSL" in protocol:
        if not KAFKA_SSL_CA_FILE:
            raise RuntimeError("KAFKA_SSL_CA_FILE is required for Kafka SSL")
        kwargs["ssl_context"] = ssl.create_default_context(cafile=KAFKA_SSL_CA_FILE)
    return kwargs


class KafkaEventBus(EventBus):
    """Kafka-шина через aiokafka. Сообщения сериализуются в JSON.

    Этап 4: BUS_CONCURRENCY ограничивает число одновременно обрабатываемых
    сообщений топика. Реальная параллельность набирается за счёт партиций
    (FSTEC_KAFKA_PARTITIONS): один консьюмер в группе получает столько партиций,
    сколько ему назначено, и обрабатывает их батчами. Ключ сообщения —
    document_id, поэтому все события одного документа попадают в одну партицию
    и сохраняют порядок, а разные документы идут вразнобой.
    """

    def __init__(self, bootstrap: str = KAFKA_BOOTSTRAP, concurrency: int | None = None,
                 group: str | None = None):
        self._bootstrap = bootstrap
        self._concurrency = max(1, concurrency if concurrency is not None else BUS_CONCURRENCY)
        self._group = group or KAFKA_CONSUMER_GROUP
        self._producer = None
        self._consumers: list[asyncio.Task] = []
        self._subscribed: set[str] = set()
        self._started = False

    async def start(self):
        from aiokafka import AIOKafkaProducer
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self._bootstrap,
            value_serializer=lambda v: json.dumps(v, ensure_ascii=False, default=str).encode("utf-8"),
            **kafka_security_kwargs(),
        )
        await self._producer.start()
        self._started = True

    async def stop(self):
        for task in self._consumers:
            task.cancel()
        for task in self._consumers:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._consumers = []
        if self._producer:
            await self._producer.stop()
            self._producer = None

    def subscribe(self, topic: str, handler: Handler) -> None:
        # Один топик = ровно один консьюмер на процесс. Дублирующая подписка
        # (повторный register_handlers/повторный вызов subscribe) создавала
        # второго члена группы на тот же топик: группа получала 2 члена при
        # 1 партиции, партиция уходила «пустому» консьюмеру -> обработка
        # вставала навсегда.
        if topic in self._subscribed:
            logger.warning("already subscribed to %s; ignoring duplicate", topic)
            return
        self._subscribed.add(topic)
        loop = asyncio.get_event_loop()
        task = loop.create_task(self._run_consumer(topic, handler))
        self._consumers.append(task)

    async def _handle(self, sem: asyncio.Semaphore | None, handler: Handler, topic: str,
                      key: str, value: dict) -> bool:
        """True — обработка успешна (offset можно коммитить), False — нет."""
        try:
            if sem is None:
                await handler(topic, key, value)
            else:
                async with sem:
                    await handler(topic, key, value)
            return True
        except Exception:
            logger.exception("Kafka handler failed topic=%s", topic)
            return False

    async def _handle_and_commit(self, consumer, sem, handler: Handler, topic: str, msg) -> None:
        from aiokafka import TopicPartition
        key = msg.key.decode("utf-8") if isinstance(msg.key, bytes) else str(msg.key)
        ok = await self._handle(sem, handler, topic, key, msg.value or {})
        if not ok:
            # НЕ коммитим offset: сообщение будет переобработано после
            # ребалансировки/рестарта, вместо того чтобы потеряться.
            logger.warning("offset not committed topic=%s key=%s (handler failed)", topic, key)
            return
        await consumer.commit({TopicPartition(msg.topic, msg.partition): msg.offset + 1})

    async def _run_consumer(self, topic: str, handler: Handler):
        from aiokafka import AIOKafkaConsumer, TopicPartition
        import time
        # Устойчивая схема: отдельный reader ТОЛЬКО опрашивает Kafka и кладёт
        # сообщения в очередь, а фиксированный пул воркеров обрабатывает их и
        # коммитит offset (контигуально). Раньше обработка шла в том же цикле,
        # что и poll, и при медленных хендлерах poll «замирал» дольше
        # max_poll_interval_ms -> CommitFailedError и вечные простои. Теперь poll
        # никогда не блокируется обработкой.
        while True:
            consumer = AIOKafkaConsumer(
                topic,
                bootstrap_servers=self._bootstrap,
                auto_offset_reset="earliest",
                enable_auto_commit=False,
                # Короткий session timeout: «зависшие»/убитые консьюмеры быстрее
                # покидают группу, и PreparingRebalance не тянется бесконечно.
                session_timeout_ms=30000,
                heartbeat_interval_ms=3000,
                max_poll_interval_ms=1800000,
                group_id=f"{self._group}-{topic}-consumer",
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
                **kafka_security_kwargs(),
            )
            try:
                await asyncio.wait_for(consumer.start(), timeout=60)
            except asyncio.CancelledError:
                # Обязательно закрываем: иначе частично стартовавший консьюмер
                # остаётся живым членом группы (утечка) -> второй член при
                # 1 партиции -> партиция уходит «пустому» -> вечный простой.
                try:
                    await asyncio.wait_for(consumer.stop(), timeout=10)
                except Exception:
                    pass
                raise
            except Exception:
                logger.exception("Kafka consumer start failed for %s; retry in 3s", topic)
                try:
                    await asyncio.wait_for(consumer.stop(), timeout=10)
                except Exception:
                    logger.debug("cleanup after failed start timed out", exc_info=True)
                await asyncio.sleep(3)
                continue

            queue: asyncio.Queue = asyncio.Queue(maxsize=2000)
            commit_lock = asyncio.Lock()
            state: dict = {}  # tp -> {"next": int|None, "done": set[int]}

            async def worker():
                while True:
                    msg = await queue.get()
                    try:
                        key = (msg.key.decode("utf-8") if isinstance(msg.key, bytes)
                               else str(msg.key))
                        ok = await self._handle(None, handler, topic, key, msg.value or {})
                        if not ok:
                            logger.warning("handler failed; offset not committed "
                                           "topic=%s key=%s", topic, key)
                            continue
                        tp = TopicPartition(msg.topic, msg.partition)
                        async with commit_lock:
                            st = state.setdefault(tp, {"next": None, "done": set()})
                            if st["next"] is None:
                                st["next"] = msg.offset
                            st["done"].add(msg.offset)
                            advanced = False
                            while st["next"] in st["done"]:
                                st["done"].discard(st["next"])
                                st["next"] += 1
                                advanced = True
                            if advanced:
                                try:
                                    await consumer.commit({tp: st["next"]})
                                except Exception:
                                    logger.debug("commit failed", exc_info=True)
                    finally:
                        queue.task_done()

            workers = [asyncio.create_task(worker())
                       for _ in range(max(1, self._concurrency))]
            last_progress = time.time()
            last_nudge = time.time()
            try:
                while True:
                    try:
                        batches = await asyncio.wait_for(
                            consumer.getmany(timeout_ms=1000,
                                             max_records=self._concurrency),
                            timeout=15)
                    except asyncio.TimeoutError:
                        batches = {}
                    got = 0
                    for _tp, msgs in batches.items():
                        for msg in msgs:
                            try:
                                queue.put_nowait(msg)
                            except asyncio.QueueFull:
                                raise RuntimeError("processing queue full; recycling")
                            got += 1
                    now = time.time()
                    if got:
                        last_progress = now
                        last_nudge = now
                    elif now - last_nudge > 3:
                        logger.debug("reader %s fetch nudge idle=%.1fs", topic, now - last_progress)
                        # Работа вокруг бага aiokafka: getmany отдаёт первую
                        # пачку и затем не возвращает новые записи, пока не
                        # выполнить seek. Переставляем позицию на текущую
                        # (без leave/join и без утечек членов группы) — это
                        # «толкает» следующий fetch. Без этого пайплайн
                        # обрабатывал батч, затем простаивал ~5 мин.
                        try:
                            assigned = consumer.assignment()
                            if not assigned:
                                logger.warning("consumer for %s has no partition assigned", topic)
                            for tp in assigned:
                                pos = await asyncio.wait_for(
                                    consumer.position(tp), timeout=5)
                                consumer.seek(tp, pos)
                        except Exception:
                            logger.debug("fetch nudge failed", exc_info=True)
                        last_nudge = now
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("Kafka consumer for %s reconnecting: %s", topic, exc)
            finally:
                for w in workers:
                    w.cancel()
                # Жёсткие таймауты: иначе stop()/join воркеров могут
                # зависнуть навсегда, reader встанет и консьюмер больше
                # никогда не пересоздастся (тихий вечный простой).
                try:
                    await asyncio.wait_for(
                        asyncio.gather(*workers, return_exceptions=True), timeout=10)
                except Exception:
                    logger.debug("worker join timed out", exc_info=True)
                try:
                    await asyncio.wait_for(consumer.stop(), timeout=10)
                except Exception:
                    logger.debug("consumer.stop() failed/timed out", exc_info=True)
            await asyncio.sleep(2)

    async def _ensure_started(self) -> None:
        """Потокобезопасный ленивый старт продюсера.

        Раньше publish делал `if not self._started: await self.start()`. При
        параллельных запросах (напр. пакетная загрузка писем в api-gateway,
        который не стартует шину на старте) несколько корутин одновременно
        создавали AIOKafkaProducer, часть проходила через ещё не готовый
        продюсер -> AttributeError '_producer_magic' (HTTP 500) и потеря
        сообщений. Лок гарантирует единственный старт.
        """
        if self._started:
            return
        lock = getattr(self, "_start_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._start_lock = lock
        async with lock:
            if not self._started:
                await self.start()

    async def publish(self, topic: str, key: str, payload: dict) -> None:
        await self._ensure_started()
        # send_and_wait дожидается подтверждения брокера (в отличие от send()+flush(),
        # который в aiokafka 0.11 в некоторых состояниях возвращался, не доставив
        # запись — из-за этого ingest терял document.parsed).
        await self._producer.send_and_wait(topic, key=key.encode("utf-8"), value=payload)


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        mode = EVENT_BUS
        if mode == "kafka":
            _bus = KafkaEventBus()
        elif mode == "sqlite":
            _bus = SqliteEventBus()
        else:
            _bus = MemoryEventBus()
    return _bus


async def publish(topic: str, key: str, payload: dict) -> None:
    await get_event_bus().publish(topic, key, payload)