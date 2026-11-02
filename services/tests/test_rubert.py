"""Тесты RuBERT-классификатора: fallback при отсутствии deps, классификация."""

import os
os.environ.setdefault("FSTEC_RUBERT_DEVICE", "cpu")
os.environ.setdefault("FSTEC_RUBERT_CONFIDENCE", "0.35")

import importlib  # noqa: E402
import pytest  # noqa: E402
import sys  # noqa: E402


def test_rubert_unavailable_without_transformers(monkeypatch):
    """Если transformers не установлен — get_rubert() возвращает None."""
    import llm_service.rubert as rubert_mod
    orig_import = __builtins__.__import__ if hasattr(__builtins__, "__import__") else __import__
    def no_transformers(name, *args, **kwargs):
        if name in ("torch", "transformers"):
            raise ImportError("mocked")
        return orig_import(name, *args, **kwargs)
    monkeypatch.setattr("builtins.__import__", no_transformers)
    rubert_mod._classifier = None
    assert rubert_mod.get_rubert() is None
    assert rubert_mod.rubert_available() is False


def test_rubert_classify_heuristic_fallback(monkeypatch):
    """Если загрузка модели невозможна — classify() возвращает (None, 0.0)."""
    from llm_service.rubert import RuBERTClassifier
    c = RuBERTClassifier()
    monkeypatch.setattr(c, "_load", lambda: False)
    assert c._load() is False
    label, conf = c.classify("хакерская группировка")
    assert label is None and conf == 0.0


def test_rubert_choose_seed(monkeypatch):
    """Классификатор выбирает метку по наибольшей косинусной близости к центроиду."""
    from llm_service.rubert import RuBERTClassifier, CATEGORY_SEEDS
    c = RuBERTClassifier()
    monkeypatch.setattr(c, "_load", lambda: True)
    # центроиды — мок: hacker(1,0,0), vulnerability(0,1,0), other(0,0,1)
    c._centroids = [
        ("hacker", _vec(1, 0, 0)),
        ("vulnerability", _vec(0, 1, 0)),
        ("other", _vec(0, 0, 1)),
    ]
    # имитируем embedding ближе к hacker
    c._tokenizer = object()
    c._model = object()
    emb = _vec(0.9, 0.1, 0.0)
    c._embed = lambda text: emb
    label, conf = c._classify_vectors(emb)
    assert label == "hacker"


def _vec(x, y, z):
    import torch
    return torch.tensor([x, y, z], dtype=torch.float32)


@pytest.mark.skipif(
    not all(importlib.util.find_spec(m) for m in ("torch", "transformers")),
    reason="torch/transformers не установлены"
)
def test_rubert_classify_with_model():
    """Если модель доступна (GPU/CPU env) — проверяем базовую классификацию."""
    from llm_service.rubert import get_rubert, rubert_available
    if not rubert_available():
        pytest.skip("модель не загрузилась (нет лимитов/диска)")
    rb = get_rubert()
    label, conf = rb.classify("хакерской группировкой осуществляется рассылка фишинговых писем с вредоносным архивом")
    assert label == "hacker"
    assert conf > 0.0
    label2, conf2 = rb.classify("уровень опасности по cvss 9.8 критический bdu:2024-12345 cve-2021-44228")
    assert label2 == "vulnerability"