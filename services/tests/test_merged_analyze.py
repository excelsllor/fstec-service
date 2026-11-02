"""Объединённый analyze_and_extract: один вызов LLM вместо analyze + extract_iocs.

Проверяем три вещи, которые легко сломать при слиянии задач:
  * IoC по-прежнему проходят анти-галлюцинацию (только дословные значения);
  * невалидная классификация даёт ретрай, но уже найденные IoC не теряются;
  * полный мусор в ответе даёт llm_used=False, чтобы конвейер ушёл в regex-фолбэк.
"""
import asyncio
import json

from llm_service.provider import LLMResult, VLLMProvider

SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

LETTER = (
    "Информируем о компрометации ресурсов. Обращаем внимание на домен "
    "evil.com и ip 104.238.149.198, а также хэш " + SHA256 + "."
)


def _provider(responses):
    """Провайдер, отдающий заранее заданные ответы вместо вызова vLLM.

    Патчатся оба пути (sync _chat и async achat): конвейер использует async-ветку,
    а прямые тесты merged-метода — sync.
    """
    p = VLLMProvider(base_url="http://vllm.invalid", model="Qwen3-8B")
    calls = []

    def fake_chat(system, user, **kwargs):
        calls.append((system, user, kwargs))
        return responses[min(len(calls) - 1, len(responses) - 1)]

    async def fake_achat(system, user, **kwargs):
        return fake_chat(system, user, **kwargs)

    p._chat = fake_chat
    p.achat = fake_achat
    return p, calls


def _reply(**kw):
    base = {"classification": "hacker", "summary": "о компрометации",
            "entities": [{"type": "organization", "value": "ФСТЭК"}],
            "iocs": {"ips": [], "domains": [], "hashes": [], "emails": []}}
    base.update(kw)
    return json.dumps(base, ensure_ascii=False)


def test_merged_returns_classification_and_iocs():
    raw = _reply(iocs={"ips": ["104.238.149.198"], "domains": ["evil.com"],
                      "hashes": [SHA256], "emails": []})
    p, calls = _provider([raw])

    res, iocs = p.analyze_and_extract(LETTER, hint="other")

    assert res.llm_used is True
    assert res.classification == "hacker"
    assert res.summary == "о компрометации"
    assert res.entities == [{"type": "organization", "value": "ФСТЭК"}]
    assert iocs is not None
    assert "104.238.149.198" in iocs.ips
    assert "evil.com" in iocs.domains
    assert len(iocs.hashes) == 1
    # один вызов вместо двух, и в него ушёл текст письма
    assert len(calls) == 1
    assert calls[0][1].startswith(LETTER[:40])


def test_merged_refangs_defanged_values():
    raw = _reply(iocs={"ips": ["104[.]238[.]149[.]198"],
                      "domains": ["evil[.]com"], "hashes": [], "emails": []})
    p, _ = _provider([raw])

    _, iocs = p.analyze_and_extract(LETTER, hint="other")

    assert iocs is not None
    assert "104.238.149.198" in iocs.ips
    assert "evil.com" in iocs.domains
    assert all("[" not in d and "]" not in d for d in iocs.domains)


def test_classifier_iocs_normalized_and_filtered():
    from llm_service.analyze import _sanitize_classifier_iocs
    from shared.extractor.ioc_extractor import IoCResult

    raw = IoCResult(
        ips=["104[.]238[.]149[.]198"],
        domains=["evil[.]com", "dr.web", "payload.dll"],
        hashes=["E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"],
        emails=["INFO@FSTEC.RU", "bad@evil.com"],
    )
    out = _sanitize_classifier_iocs(raw)

    assert out.ips == ["104.238.149.198"]
    assert out.domains == ["evil.com"]
    assert out.hashes == [raw.hashes[0].lower()]
    assert out.emails == ["bad@evil.com"]


def test_merged_drops_hallucinated_iocs():
    """Значения, которых нет в тексте письма, отбрасываются."""
    raw = _reply(iocs={"ips": ["8.8.8.8"], "domains": ["good.com"],
                      "hashes": [], "emails": []})
    p, _ = _provider([raw])

    _, iocs = p.analyze_and_extract(LETTER, hint="other")

    assert iocs is not None
    assert "8.8.8.8" not in iocs.ips
    assert "good.com" not in iocs.domains
    # настоящий домен при этом сохранился не потерялся вместе с выдуманным
    assert "evil.com" not in iocs.domains  # его в ответе модели не было


def test_merged_retries_on_invalid_classification_and_keeps_iocs():
    """Первая попытка — мусорный classification; IoC из неё не теряются."""
    bad = _reply(classification="непонятно",
                 iocs={"ips": ["104.238.149.198"], "domains": [], "hashes": [], "emails": []})
    good = _reply(classification="vulnerability",
                  iocs={"ips": [], "domains": [], "hashes": [], "emails": []})
    p, calls = _provider([bad, good])

    res, iocs = p.analyze_and_extract(LETTER, hint="other")

    assert len(calls) == 2, "невалидная классификация обязана вызвать ретрай"
    assert res.classification == "vulnerability"
    # IoC из первой (невалидной) попытки сохранены
    assert iocs is not None and "104.238.149.198" in iocs.ips


def test_merged_keeps_iocs_when_all_attempts_invalid():
    """Обе попытки с мусорной схемой: IoC не теряем, классификация — из hint."""
    bad = _reply(classification="???", iocs={"ips": ["104.238.149.198"],
                                             "domains": [], "hashes": [], "emails": []})
    p, calls = _provider([bad])

    res, iocs = p.analyze_and_extract(LETTER, hint="vulnerability")

    assert len(calls) == 2
    assert iocs is not None and "104.238.149.198" in iocs.ips
    assert res.classification == "vulnerability", "должен сработать фолбэк на hint"


def test_merged_garbage_response_falls_back_to_regex():
    p, calls = _provider(["не json вовсе"])

    res, iocs = p.analyze_and_extract(LETTER, hint="other")

    assert isinstance(res, LLMResult)
    assert res.llm_used is False, "мусорный ответ = фолбэк на regex, а не llm_used"
    assert iocs is None


def test_merged_empty_text_does_not_call_llm():
    p, calls = _provider([_reply()])

    res, iocs = p.analyze_and_extract("   ", hint="other")

    assert calls == [], "пустой текст не должен дёргать LLM"
    assert res.llm_used is False and iocs is None


def test_merged_async_matches_sync():
    raw = _reply(iocs={"domains": ["evil.com"], "ips": [], "hashes": [], "emails": []})
    p, _ = _provider([raw])

    res, iocs = asyncio.run(p.analyze_and_extract_async(LETTER, hint="other"))

    assert res.llm_used is True
    assert res.classification == "hacker"
    assert iocs is not None and "evil.com" in iocs.domains


def test_analyze_async_uses_single_merged_call(monkeypatch):
    """При FSTEC_LLM_MERGED_ANALYZE=1 обвязка делает один вызов LLM на письмо.

    По умолчанию merged ВЫКЛ (см. test_analyze_async_default_uses_two_calls):
    на крупных письмах merged уходит в runaway-генерацию и медленнее.
    """
    from llm_service import analyze as an

    monkeypatch.setattr(an, "LLM_MERGED_ANALYZE", True)

    raw = _reply(iocs={"ips": ["104.238.149.198"], "domains": ["evil.com"],
                      "hashes": [], "emails": []})
    p, calls = _provider([raw])

    event, _ = asyncio.run(an.analyze_async(p, LETTER))

    assert len(calls) == 1, "на письмо должен быть ровно один вызов LLM"
    assert event.classification in ("hacker", "compromise", "vulnerability", "other")
    assert event.llm_used is True
    assert "104.238.149.198" in event.iocs.ip_addresses
    assert "evil.com" in event.iocs.domains


def test_analyze_async_default_uses_two_calls(monkeypatch):
    """По умолчанию (merged выключен) — два вызова: analyze + extract_iocs."""
    from llm_service import analyze as an

    monkeypatch.setattr(an, "LLM_MERGED_ANALYZE", False)

    analyze_reply = _reply(iocs={}, summary="кратко")
    extract_reply = _reply(iocs={"ips": ["104.238.149.198"], "domains": ["evil.com"],
                                 "hashes": [], "emails": []})
    p, calls = _provider([extract_reply, analyze_reply])

    event, _ = asyncio.run(an.analyze_async(p, LETTER))

    assert len(calls) == 2, "два независимых вызова LLM (IoC + классификация)"
    assert event.llm_used is True
    assert "104.238.149.198" in event.iocs.ip_addresses
    assert "evil.com" in event.iocs.domains


def test_analyze_async_falls_back_when_provider_has_no_merged():
    """Провайдер без merged-метода (тестовые фейки) — прежние два вызова."""
    from llm_service.analyze import analyze_async

    class LegacyProvider:
        def extract_iocs_llm(self, text):
            return None

        def analyze(self, text, hint=None):
            return LLMResult(classification="hacker", llm_used=True)

    event, _ = asyncio.run(analyze_async(LegacyProvider(), LETTER))
    assert event.classification in ("hacker", "compromise", "vulnerability", "other")


def test_merged_chunks_large_letter_and_merges_iocs():
    """B: длинное письмо режется на чанки; вызов на каждый чанк; IoC объединяются."""
    p, calls = _provider([
        _reply(iocs={"ips": ["104.238.149.198"], "domains": [], "hashes": [], "emails": []}),
        _reply(iocs={"ips": [], "domains": ["evil.com"], "hashes": [], "emails": []}),
    ])
    part1 = "A" * (p._MERGED_MAX_CHARS - 100) + " ip 104.238.149.198."
    part2 = "B" * (p._MERGED_MAX_CHARS - 100) + " домен evil.com."
    long_letter = part1 + "\n\n" + part2
    assert len(p._chunk_text(long_letter)) == 2

    res, iocs = p.analyze_and_extract(long_letter, hint="other")

    assert len(calls) == 2, "на каждый чанк должен быть отдельный вызов"
    assert res.classification == "hacker"
    assert iocs is not None
    assert "104.238.149.198" in iocs.ips      # IoC из первого чанка
    assert "evil.com" in iocs.domains         # IoC из второго чанка
