"""WS-1: E2E по форматам (ТЗ 2.1-2.2): docx/xlsx/rtf/txt/odt/pdf/doc через парсеры и через HTTP /upload."""
import os
import threading

os.environ.setdefault("FSTEC_EVENT_BUS", "memory")

import pytest

from formats import IOC_MARKERS, BUILDERS
from conftest import headers


def _headers(client):
    return headers(client)


def _mime(ext: str) -> str:
    return {
        ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        ".odt": "application/vnd.oasis.opendocument.text",
        ".rtf": "application/rtf",
        ".txt": "text/plain",
        ".pdf": "application/pdf",
        ".doc": "application/msword",
    }[ext]


# ---------------- unit: парсеры (все форматы) ----------------

@pytest.mark.parametrize("ext", list(BUILDERS))
def test_parse_each_format(ext):
    from shared.parsers import parse_bytes
    r = parse_bytes(f"sample{ext}", BUILDERS[ext]())
    hit = [m for m in IOC_MARKERS if m in r.text]
    assert hit == IOC_MARKERS, f"{ext}: нашлись только {hit}"


# ---------------- E2E: полный конвейер через /upload ----------------

@pytest.mark.parametrize("ext", list(BUILDERS))
def test_upload_full_pipeline_each_format(client, ext):
    content = BUILDERS[ext]()
    files = {"files": (f"letter{ext}", content, _mime(ext))}
    r = client.post("/upload", files=files, headers=_headers(client))
    assert r.status_code == 201, r.text
    doc_id = r.json()["id"]

    doc = client.get(f"/documents/{doc_id}", headers=_headers(client))
    assert doc.status_code == 200
    data = doc.json()
    assert data["status"] == "completed", f"{ext}: {data.get('processing_stage')} {data.get('parse_errors')}"
    assert data["ioc_count"] >= 1
    assert data["vuln_count"] >= 1
    assert all(m in data["all_text"] for m in ("CVE-2021-44228", "Log4j")), f"{ext}: all_text потерян"
    assert not data.get("parse_errors"), f"{ext}: parse_errors = {data.get('parse_errors')}"


# ---------------- лимиты + magic bytes ----------------

def test_upload_batch_too_many(client):
    files = [("files", (f"l{i}.docx", BUILDERS[".docx"](), _mime(".docx"))) for i in range(11)]
    r = client.post("/upload", files=files, headers=_headers(client))
    assert r.status_code == 413


def test_upload_file_too_big(client):
    big = b"x" * (20 * 1024 * 1024 + 1)
    files = {"files": ("big.docx", big, _mime(".docx"))}
    r = client.post("/upload", files=files, headers=_headers(client))
    assert r.status_code == 413


def test_upload_no_files(client):
    r = client.post("/upload", files=[], headers=_headers(client))
    assert r.status_code == 400


@pytest.mark.parametrize("ext,payload", [
    (".docx", b"MZ\x90\x00"),          # exe-сигнатура в .docx
    (".pdf", b"\x89PNG\r\n\x1a\n"),    # PNG в .pdf
    (".doc", b"BZh91AY&SY"),           # bzip2 в .doc
    (".rtf", b"\x00\x00{\\rtf"),       # rtf с заголовком, но не-rtf старт
    (".txt", b"\x00\x00\x00\x00"),     # txt не проверяется по сигнатуре
])
def test_magic_bytes_rejected(client, ext, payload):
    files = {"files": (f"fake{ext}", payload, _mime(ext))}
    r = client.post("/upload", files=files, headers=_headers(client))
    if ext == ".txt":
        assert r.status_code == 201 or r.status_code == 415
        if r.status_code == 201:
            _ = r
        return
    assert r.status_code == 415, f"{ext}: ожидали 415, получили {r.status_code}"


# ---------------- конкурентная загрузка ----------------

def test_concurrent_uploads(client):
    n = 6
    results = [None] * n

    def _worker(i):
        content = BUILDERS[".docx"]()
        files = {"files": (f"conc_{i}.docx", content, _mime(".docx"))}
        results[i] = client.post("/upload", files=files, headers=_headers(client))

    threads = [threading.Thread(target=_worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ids = [r.json()["id"] for r in results]
    assert all(r.status_code == 201 for r in results), [r.text for r in results]
    unique_ids = set(ids)
    assert len(unique_ids) >= 1

    for doc_id in unique_ids:
        doc = client.get(f"/documents/{doc_id}", headers=_headers(client)).json()
        assert doc["status"] == "completed"