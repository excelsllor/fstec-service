"""Пайплайн анализа документа (llm-service): regex-first + LLM-валидация.

Сохраняет: entities, iocs, threats, vulns_raw, summary, классификацию.
Возвращает DocumentAnalyzed для публикации в document.analyzed.
"""
import logging
import re

from sqlalchemy.orm import Session

from shared.events import AnalysisIocs, DocumentAnalyzed
from shared.config import (LLM_MERGED_ANALYZE, LLM_MERGED_VULN, IOC_CLASSIFIER_URL,
                           BERT_PRIMARY_IOCS, DEDUPE_PROMPT_LINES)
from shared.extractor.ioc_extractor import (
    INTERNAL_EMAILS, IoCResult, _clean_domain, _valid_domain, extract_iocs,
)
from shared.extractor.letter_analyzer import analyze_letter
from shared.extractor.ner import extract_standard_ner
from shared.extractor.patterns import EMAIL_PATTERN
from shared.extractor.summary import summarize_heuristic
from shared.extractor.vuln_extractor import extract_software_items, extract_vulns
from shared.models import Document, Entity, IoC, Summary, Threat
from llm_service.provider import LLMProvider, _norm_ip, _refang
from llm_service.rubert import rubert_available, get_rubert

logger = logging.getLogger("fstec.llm")

# Анти-prompt-injection: маркеры инструкций внутри письма (недоверенный ввод).
# При срабатывании LLM-summary отбрасывается в пользу эвристической сводки.
_INJECTION_RE = re.compile(
    r"(игнориру[йт]|ignore\s+(all\s+)?(previous|prior|above)|"
    r"system\s*prompt|системн\w+\s+промпт|выведи\s+(полностью\s+)?(систем|инструкц)|"
    r"disclose\s+(your\s+)?(system|prompt)|output\s+only|не\s+выполняй)",
    re.IGNORECASE,
)


def _clip(value, limit: int) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit]


def _sanitize_summary(text: str, fallback: str) -> str:
    s = " ".join((text or "").split())
    fb = _clip(" ".join((fallback or "").split()), 500)
    if not s:
        return fb
    if _INJECTION_RE.search(s):
        logger.warning("LLM summary rejected (injection pattern): %.160s", s)
        return fb
    if len(s) < 20 or len(s.split()) < 3:
        logger.warning("LLM summary rejected (non-prose output): %.80s", s)
        return fb
    return _clip(s, 500)

# Веса SLA: критичность (ТЗ 2.4 / Национальный стандарт правил категорирования)
THREAT_WEIGHTS = {
    "malware_attack": 1.4,
    "compromise": 1.3,
    "phishing": 1.1,
    "clickfix": 1.5,
    "vulnerability": 1.2,
}
VULN_WEIGHTS = {"critical": 1.8, "high": 1.6, "medium": 1.3, "low": 1.0, "unknown": 1.2}


def _dedupe_prompt_lines(text: str) -> str:
    """Убирает точные повторы длинных строк (колонтитулы/шапки) из LLM-промпта."""
    seen = set()
    out = []
    for raw in text.splitlines():
        line = re.sub(r"\s+", " ", raw).strip()
        if len(line) >= 40 and line in seen:
            continue
        if len(line) >= 40:
            seen.add(line)
        out.append(raw)
    return "\n".join(out)


def _regex_pass(text: str):
    """Детерминированная часть анализа (без LLM). Вынесена отдельно, чтобы её
    можно было выполнить в потоке, не блокируя event loop (этап 4)."""
    return (analyze_letter(text), extract_iocs(text), extract_vulns(text),
            extract_standard_ner(text), summarize_heuristic(text))


def analyze(provider: LLMProvider, text: str) -> tuple[DocumentAnalyzed, dict]:
    """Анализ текста: результат события + ddl-промежуточные данные для БД."""
    letter, iocs, vulns, ner, summary = _regex_pass(text)

    # IoC: гибрид regex ∪ LLM (LLM-слой с анти-галлюцинацией подтверждает/дополняет).
    # Провайдеры duck-typed (тесты/фейки) могут не иметь этих методов — безопасный вызов.
    _extract_llm = getattr(provider, "extract_iocs_llm", None)
    llm_io = _extract_llm(text) if callable(_extract_llm) else None
    if llm_io:
        _merge_iocs(iocs, _sanitize_classifier_iocs(llm_io, text))

    # Классификация: regex-first (ТЗ 2.3) → RuBERT (если regex не определил) →
    # LLM-классификация типов (3 класса, авторитетный слой — сверка 22/22 vs 12/22)
    # → сведение compromise → hacker.
    classification = letter.letter_type
    if classification == "other" and rubert_available():
        rl, conf = get_rubert().classify(text)
        if rl and conf:
            classification = rl
    _classify = getattr(provider, "classify_type", None)
    llm_cls = _classify(text) if callable(_classify) else ""
    llm_result = provider.analyze(text, hint=classification)
    return _finalize(text, letter, iocs, vulns, ner, summary, classification,
                     llm_cls, llm_result)


async def analyze_async(provider: LLMProvider, text: str) -> tuple[DocumentAnalyzed, dict]:
    """Асинхронный twin analyze() для конвейера (этап 4).

    Два отличия от синхронной версии:
      * детерминированный regex-проход уходит в поток — event loop продолжает
        принимать события, пока считаются выражения;
      * три вызова LLM (IoC, classify_type, analyze) идут одновременно, а не
        последовательно. Они независимы: hint для analyze берётся из regex/RuBERT,
        а не из результата classify_type.
    Если провайдер не имеет async-методов (тестовые фейки) — используется
    синхронный путь в потоке, поведение остаётся прежним."""
    import asyncio

    from shared.concurrency import run_blocking

    letter, iocs, vulns, ner, summary = await run_blocking(_regex_pass, text)

    classification = letter.letter_type
    if classification == "other" and rubert_available():
        rl, conf = await run_blocking(get_rubert().classify, text)
        if rl and conf:
            classification = rl

    async def _maybe(name: str, *args, **kwargs):
        """Вызвать provider.<name>_async, если он есть, иначе sync-версию в потоке."""
        fn = getattr(provider, f"{name}_async", None)
        if fn is not None:
            return await fn(*args, **kwargs)
        sync_fn = getattr(provider, name, None)
        if not callable(sync_fn):
            return None
        return await run_blocking(sync_fn, *args, **kwargs)

    # Один вызов LLM вместо двух: classify_type уже удалён из async-пути, а
    # analyze и extract_iocs оба просили classification и оба получали полный
    # текст письма (~4.4k + ~5.2k токенов префилла на документ). Объединённый
    # analyze_and_extract префиллит текст один раз. Провайдеры без метода
    # (тестовые фейки) сохраняют прежнее поведение.
    # IoC из внешнего BERT-классификатора запускаем ПАРАЛЛЕЛЬНО с 8B-вызовом,
    # чтобы его латентность (CPU) не добавлялась к критическому пути.
    llm_text = _dedupe_prompt_lines(text) if DEDUPE_PROMPT_LINES else text
    clf_task = asyncio.ensure_future(_classifier_iocs_async(text))
    # merged быстрее на hacker/other-письмах; для regex-vulnerability оставляем
    # два вызова, чтобы не менять проверенное поведение на больших BDU-списках.
    merged_used = False
    is_vuln_doc = classification == "vulnerability" or len(vulns) >= 3
    bert_primary = (is_vuln_doc and BERT_PRIMARY_IOCS
                    and bool(IOC_CLASSIFIER_URL))
    if bert_primary:
        # BERT видит весь текст (<=20k), regex дополняет; отдельный LLM-IoC
        # вызов не нужен. Если BERT упадёт — fallback ниже.
        llm_io = None
        llm_result = await _maybe("analyze", llm_text, hint=classification)
    elif (LLM_MERGED_ANALYZE and (not is_vuln_doc or LLM_MERGED_VULN)
            and callable(getattr(provider, "analyze_and_extract", None))):
        merged_used = True
        merged = await _maybe("analyze_and_extract", llm_text, hint=classification)
        llm_result, llm_io = merged if merged else (None, None)
    else:
        llm_io, llm_result = await asyncio.gather(
            _maybe("extract_iocs_llm", text),
            _maybe("analyze", llm_text, hint=classification),
        )
    clf_io = await clf_task
    if bert_primary and clf_io is None:
        logger.warning("BERT IoC unavailable; fallback to LLM IoC extraction")
        llm_io = await _maybe("extract_iocs_llm", text)
    if merged_used and llm_io is None and clf_io is None:
        # BERT-классификатор недоступен, а merged-промпт не просит IoC.
        # Не теряем качество: добираем IoC отдельным LLM-вызовом.
        logger.warning("IoC classifier unavailable; fallback to LLM IoC extraction")
        llm_io = await _maybe("extract_iocs_llm", text)
    if llm_result is None:
        from llm_service.provider import LLMResult
        llm_result = LLMResult(llm_used=False)
    if llm_io:
        _merge_iocs(iocs, _sanitize_classifier_iocs(llm_io, text))
    if clf_io:
        _merge_iocs(iocs, _sanitize_classifier_iocs(clf_io, text))
    _expand_parent_domains(iocs)
    return _finalize(text, letter, iocs, vulns, ner, summary, classification,
                     "", llm_result)


async def _classifier_iocs_async(text: str):
    """IoC из внешнего EuroBERT-классификатора. None при недоступности."""
    from shared.config import IOC_CLASSIFIER_URL
    if not IOC_CLASSIFIER_URL or not text.strip():
        return None
    import httpx
    from shared.extractor.ioc_extractor import IoCResult
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            resp = await client.post(IOC_CLASSIFIER_URL, json={"text": text})
            if resp.status_code != 200:
                return None
            d = resp.json()
    except Exception:
        logger.warning("IoC classifier unavailable", exc_info=True)
        return None
    res = IoCResult()
    res.ips += [v for v in d.get("ips", []) if v not in res.ips]
    res.domains += [v for v in d.get("domains", []) if v not in res.domains]
    res.hashes += [v for v in d.get("hashes", []) if v not in res.hashes]
    res.emails += [v for v in d.get("emails", []) if v not in res.emails]
    res.vuln_ids += [v for v in d.get("bdu", []) if v not in res.vuln_ids]
    res.cve_ids += [v for v in d.get("cve", []) if v not in res.cve_ids]
    return res


def _finalize(text, letter, iocs, vulns, ner, summary, classification,
              llm_cls, llm_result) -> tuple[DocumentAnalyzed, dict]:
    """Сведение результатов regex/LLM в событие document.analyzed."""
    if llm_result.llm_used and llm_result.classification in ("hacker", "compromise", "vulnerability", "other"):
        if not llm_cls:
            classification = llm_result.classification
        else:
            # классификация из analyze() уже покрыта слоем classify_type (3 класса)
            classification = llm_cls
    if llm_result.summary:
        summary = _sanitize_summary(llm_result.summary, summary)
    if llm_result.entities:
        ner.organizations = [e["value"] for e in llm_result.entities if e.get("type") == "organization"] or ner.organizations
        ner.deadlines = [e["value"] for e in llm_result.entities if e.get("type") == "deadline"] or ner.deadlines
        ner.contacts = [e["value"] for e in llm_result.entities if e.get("type") == "contact"] or ner.contacts

    # сведение типов к 3: compromise -> hacker (блоки ответа сохраняют threat_type compromise)

    threats = [{"number": t.number, "threat_type": t.threat_type, "group_name": t.group_name,
                "theme": t.theme, "archive_name": t.archive_name, "exe_name": t.exe_name,
                "malware_type": t.malware_type, "description": t.description,
                "measures": t.measures} for t in letter.threats]
    if classification == "compromise" and threats and any(
            t.get("threat_type") in {"phishing", "malware_attack", "clickfix", "vulnerability"}
            for t in threats):
        classification = "hacker"
    vuln_items = [{"bdu_id": v.bdu_id, "cve_id": v.cve_id, "description": v.description,
                   "software": v.software, "version": v.version, "severity": v.severity} for v in vulns]
    if vuln_items and not threats and classification in ("hacker", "other"):
        # Письмо без threat-блоков, но с конкретными CVE/BDU — это письмо об уязвимостях.
        classification = "vulnerability"

    entities_out = [
        {"type": "organization", "value": o} for o in ner.organizations
    ] + [
        {"type": "deadline", "value": d} for d in ner.deadlines
    ] + [
        {"type": "contact", "value": c} for c in ner.contacts
    ]

    software_items = extract_software_items(text)
    for v in vulns:
        if v.software and not any(s["name"] == v.software and s.get("version") == v.version for s in software_items):
            software_items.append({"name": v.software, "version": v.version})

    existing_entities = {(e["type"], e["value"]) for e in entities_out}
    for s in software_items:
        value = f"{s['name']} {s['version']}".strip()
        if value and ("software", value) not in existing_entities:
            entities_out.append({"type": "software", "value": value})
            existing_entities.add(("software", value))

    event = DocumentAnalyzed(
        document_id=0,
        classification=classification,
        letter_number=letter.letter_number,
        letter_date=letter.letter_date,
        summary=summary,
        entities=entities_out,
        iocs=AnalysisIocs(
            ip_addresses=iocs.ips,
            ipv4_cidr=iocs.ipv4_cidr,
            ipv6=iocs.ipv6,
            domains=iocs.domains,
            hashes=iocs.hashes,
            urls=iocs.vdb_urls,
            emails=iocs.emails,
            cve=iocs.cve_ids,
            bdu=iocs.vuln_ids,
            software=software_items,
        ),
        threats=threats,
        vulns_raw=vuln_items,
        llm_used=llm_result.llm_used,
    )
    return event, {
        "letter_number": letter.letter_number,
        "letter_date": letter.letter_date,
        "classification": classification,
        "domains": iocs.domains,
    }


def _merge_iocs(base, llm):
    """Гибрид: добавляем в regex-базу только те значения, что предложила модель."""
    for attr, src in (("ips", "ips"), ("ipv6", "ipv6"), ("domains", "domains"),
                      ("hashes", "hashes"), ("emails", "emails")):
        existing = set(getattr(base, src))
        for v in getattr(llm, src):
            if v not in existing:
                getattr(base, src).append(v)
                existing.add(v)


def _classifier_value_in_text(value: str, text: str) -> bool:
    if not text:
        return True
    needle = value.strip().lower()
    hay = text.lower()
    norm_hay = (hay.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
                .replace("[:]", ":"))
    norm_needle = (needle.replace("[.]", ".").replace("(.)", ".").replace("[dot]", ".")
                   .replace("[:]", ":"))
    if not norm_needle:
        return False
    pattern = r"(?<![0-9a-z_.@-])" + re.escape(norm_needle) + r"(?![0-9a-z_.@-])"
    return re.search(pattern, norm_hay, re.IGNORECASE) is not None


def _sanitize_classifier_iocs(res, text: str = ""):
    """Нормализация ответа BERT: refang, типы, FP-фильтры и проверка по тексту."""
    out = IoCResult()
    seen = set()
    for value in res.ips:
        v = _refang(str(value))
        ip = _norm_ip(v)
        if ip and ip not in seen and _classifier_value_in_text(ip, text):
            seen.add(ip)
            out.ips.append(ip)
    for value in res.domains:
        v = _refang(str(value)).strip()
        ip = _norm_ip(v.split("/", 1)[0].split(":", 1)[0])
        if ip:
            if ip not in seen and _classifier_value_in_text(ip, text):
                seen.add(ip)
                out.ips.append(ip)
            continue
        d = _clean_domain(v)
        if d and d not in seen and _valid_domain(d, obfuscated=False) \
                and _classifier_value_in_text(d, text):
            seen.add(d)
            out.domains.append(d)
    for value in res.hashes:
        h = _refang(str(value)).strip().lower()
        if re.fullmatch(r"[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64}|[0-9a-f]{96}|[0-9a-f]{128}", h):
            if h not in seen and _classifier_value_in_text(h, text):
                seen.add(h)
                out.hashes.append(h)
    for value in res.emails:
        e = _refang(str(value)).strip().lower()
        if EMAIL_PATTERN.match(e) and e not in INTERNAL_EMAILS and e not in seen \
                and _classifier_value_in_text(e, text):
            seen.add(e)
            out.emails.append(e)
    out.vuln_ids = [v for v in res.vuln_ids if _classifier_value_in_text(str(v), text)]
    out.cve_ids = [v for v in res.cve_ids if _classifier_value_in_text(str(v), text)]
    return out


def _expand_parent_domains(iocs: IoCResult) -> None:
    """Добавляет родительский домен, если в тексте есть >=2 его поддомена."""
    from collections import Counter
    counts = Counter()
    for d in iocs.domains:
        parts = d.split(".")
        if len(parts) >= 3:
            counts[".".join(parts[-2:])] += 1
    existing = set(iocs.domains)
    for parent, count in counts.items():
        if count >= 2 and parent not in existing and parent not in {"fstec.ru"}:
            iocs.domains.append(parent)
            existing.add(parent)


def persist_analysis(db: Session, doc: Document, event: DocumentAnalyzed) -> None:
    doc.letter_number = event.letter_number
    doc.letter_date = event.letter_date
    doc.letter_type = event.classification
    doc.processing_stage = "analyzed"
    doc.status = "analyzed"
    db.query(IoC).filter(IoC.document_id == doc.id).delete()
    db.query(Threat).filter(Threat.document_id == doc.id).delete()
    db.query(Entity).filter(Entity.document_id == doc.id).delete()
    db.query(Summary).filter(Summary.document_id == doc.id).delete()

    for ioc_type, values in [
        ("ip", event.iocs.ip_addresses),
        ("ip_cidr", event.iocs.ipv4_cidr),
        ("ipv6", event.iocs.ipv6),
        ("domain", event.iocs.domains),
        ("hash", event.iocs.hashes),
        ("url", event.iocs.urls),
        ("email", event.iocs.emails),
        ("cve", event.iocs.cve),
        ("bdu", event.iocs.bdu),
    ]:
        for v in values:
            v = _clip(v, 500)
            if not v:
                continue
            db.add(IoC(document_id=doc.id, ioc_type=ioc_type, value=v,
                       source="regex" if not event.llm_used else "llm",
                       llm_validated=event.llm_used))

    for t in event.threats:
        db.add(Threat(document_id=doc.id, number=t.get("number", 0),
                      threat_type=_clip(t.get("threat_type", ""), 50),
                      group_name=_clip(t.get("group_name", ""), 200),
                      theme=_clip(t.get("theme", ""), 500),
                      archive_name=_clip(t.get("archive_name", ""), 300),
                      exe_name=_clip(t.get("exe_name", ""), 300),
                      malware_type=_clip(t.get("malware_type", ""), 200),
                      description=t.get("description", ""),
                      measures="\n".join(t.get("measures", []))))

    for e in event.entities:
        etype = e.get("type") if isinstance(e, dict) else e.type
        evalue = _clip(e.get("value") if isinstance(e, dict) else e.value, 500)
        if not evalue:
            continue
        db.add(Entity(document_id=doc.id, entity_type=etype, value=evalue))

    conf = 0.9 if event.llm_used else 0.6
    db.add(Summary(document_id=doc.id, summary=_clip(event.summary, 500), confidence=conf))
    db.commit()


def compute_sla(classification: str, threat_count: int, vuln_severities: list[str], domain_count: int) -> tuple[str, str]:
    """SLA normal|critical и routing default|infosec (категорирование, ТЗ 2.4)."""
    score = 1.0
    if threat_count:
        score *= min(2.0, THREAT_WEIGHTS.get(classification, 1.0) * (1 + threat_count * 0.1))
    for sev in vuln_severities:
        score *= VULN_WEIGHTS.get(sev, 1.2)
    score *= 1.0 if domain_count == 0 else min(1.5, 1.0 + 0.1 * domain_count)
    sla = "critical" if score >= 1.6 else "normal"
    routing = "infosec" if classification in ("compromise", "clickfix") or "critical" in vuln_severities else "default"
    return sla, routing