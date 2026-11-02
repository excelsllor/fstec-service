"""Регистр запущенных сервисов для диагностики.

Каждый worker/gateway пишет при старте файл services/data/registry/<name>.json
с pid/временем старта. Диагностика (GET /api/diagnostics) читает их и
определяет живость процесса через psutil.pid_exists.
"""
import json
import os
import time

from pathlib import Path

from shared.config import DATA_DIR

_REG_DIR = None


def _dir() -> Path:
    global _REG_DIR
    if _REG_DIR is None:
        _REG_DIR = Path(DATA_DIR) / "registry"
    _REG_DIR.mkdir(parents=True, exist_ok=True)
    return _REG_DIR


def _path(name: str) -> Path:
    return _dir() / f"{name}.json"


def _write_registry(name: str, data: dict) -> None:
    """???????? ?????????? heartbeat, ????? ??????????? ?? ?????? ?????? JSON."""
    p = _path(name)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, p)


def register_service(name: str) -> None:
    data = {"pid": os.getpid(), "started": time.time(), "last_seen": time.time()}
    _write_registry(name, data)


def touch_service(name: str) -> None:
    p = _path(name)
    if not p.exists():
        register_service(name)
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8") or "{}")
        data["pid"] = os.getpid()
        data["last_seen"] = time.time()
        data.setdefault("started", time.time())
        _write_registry(name, data)
    except Exception:
        register_service(name)


def read_services() -> list[dict]:
    import psutil
    out = []
    for p in sorted(_dir().glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8") or "{}")
            pid = data.get("pid")
            alive = False
            try:
                alive = pid is not None and psutil.pid_exists(int(pid))
            except Exception:
                pass
            out.append({
                "name": p.stem,
                "pid": pid,
                "started": data.get("started"),
                "last_seen": data.get("last_seen"),
                "alive": alive,
            })
        except Exception:
            continue
    return out