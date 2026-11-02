"""Ограничители параллелизма для конвейера (этап 4).

До этого изменение обработка была строго последовательной: один event loop на воркер,
а внутри обработчика синхронный вызов vLLM на десятки секунд. Пока шёл один запрос,
второе письмо даже не читалось из шины.

Здесь собраны три примитива:
  * gate()          — семафор на «дорогой» внешний ресурс (vLLM, внешние БД);
  * run_blocking()  — вынос блокирующего (CPU/DB/файл/ sync-HTTP) кода в поток,
                      чтобы event loop продолжал принимать и отдавать события;
  * bounded_gather() — запуск N задач с потолком одновременного исполнения.

Семафоры кэшируются по ключу и привязаны к текущему event loop: asyncio.Semaphore
нельзя переиспользовать между разными петлями (в тестах и при перезапуске воркера
петля создаётся заново).
"""
import asyncio
import logging
from typing import Awaitable, Callable, Sequence, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")

_gates: dict[str, asyncio.Semaphore] = {}
_gates_loop_id: int | None = None


def gate(name: str, limit: int) -> asyncio.Semaphore:
    """Семафор с именем name на текущем event loop. limit <= 0 трактуется как 1."""
    if limit <= 0:
        limit = 1
    global _gates_loop_id
    try:
        loop_id = id(asyncio.get_running_loop())
    except RuntimeError:
        # Вне петли (sync-код) отдаём обычный семафор: использовать его через
        # await в этом контексте всё равно нельзя.
        return asyncio.Semaphore(limit)
    if _gates_loop_id != loop_id:
        # Другая петля (тест, перезапуск воркера) — предыдущие семафоры непригодны.
        _gates.clear()
        _gates_loop_id = loop_id
    sem = _gates.get(name)
    if sem is None:
        sem = asyncio.Semaphore(limit)
        _gates[name] = sem
    return sem


async def run_blocking(fn: Callable[..., T], *args, **kwargs) -> T:
    """Выполнить блокирующую функцию в потоке, не блокируя event loop."""
    return await asyncio.to_thread(fn, *args, **kwargs)


async def bounded_gather(coros: Sequence[Awaitable[T]], limit: int,
                         name: str = "work") -> list[T]:
    """await список awaitable'ов, но не более limit одновременно.

    Порядок результатов совпадает с порядком входных awaitable'ов. Исключения не
    подавляются: вызывающий код решает, что с ними делать (обычно это осознанный
    fallback, а не падение всего документа)."""
    items = list(coros)
    if not items:
        return []
    if limit <= 0 or limit >= len(items):
        return list(await asyncio.gather(*items))
    sem = gate(f"bounded:{name}", limit)
    results: list[T] = [None] * len(items)  # type: ignore[list-item]

    async def _one(index: int, awaitable: Awaitable[T]) -> None:
        async with sem:
            results[index] = await awaitable

    await asyncio.gather(*(_one(i, a) for i, a in enumerate(items)))
    return results


def reset_gates() -> None:
    """Сбросить кэш семафоров (используется в тестах)."""
    global _gates_loop_id
    _gates.clear()
    _gates_loop_id = None
