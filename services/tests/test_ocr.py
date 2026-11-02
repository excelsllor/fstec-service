"""Тесты OCR-провайдеров (Tesseract/Paddle) и fallback."""

import os

os.environ.setdefault("FSTEC_OCR_ENGINE", "auto")
os.environ.setdefault("FSTEC_OCR_DEVICE", "cpu")
os.environ.setdefault("FSTEC_OCR_ENABLED", "false")

from shared.parsers.ocr import ocr_pdf_bytes, ocr_needed  # noqa: E402


def test_ocr_needed():
    assert ocr_needed("", 20) is True
    assert ocr_needed("a" * 21, 20) is False
    assert ocr_needed(None, 20) is True


def test_ocr_pdf_returns_tuple():
    text, errors = ocr_pdf_bytes(b"%PDF-1.4 test", lang="rus")
    assert isinstance(text, str)
    assert isinstance(errors, list)


def test_engine_auto_fallback(monkeypatch):
    monkeypatch.setenv("FSTEC_OCR_ENGINE", "auto")
    text, errs = ocr_pdf_bytes(b"%PDF-1.4 empty")
    assert isinstance(errs, list)


def test_engine_tesseract_explicit(monkeypatch):
    monkeypatch.setenv("FSTEC_OCR_ENGINE", "tesseract")
    text, errs = ocr_pdf_bytes(b"%PDF-1.4 empty")
    assert isinstance(errs, list)