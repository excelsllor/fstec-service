"""Шаблонный проект ответа (ТЗ 2.5.2) с библиотекой мер и LLM-подбором.

Отличие от response_generator: шапка/intro/outro из шаблонов (reply_templates),
блоки описываются планом {fragment_key, measures[]}, меры выбираются LLM из
библиотеки (measures), придуманные LLM меры помечаются source="new" и пишутся
в measure_candidates (очередь админа). При недоступном LLM — детерминированный
fallback (по образцу response_generator), чтобы ответ всегда собирался.
"""
import copy
import hashlib
import json
import logging
import os
import re

from shared.config import LLM_PROVIDER, ORG_NAME
from shared.generator.response_generator import _clean_theme, render_reply_docx

logger = logging.getLogger("fstec.reply")

_PLAN_CACHE: dict[str, dict] = {}
_PLAN_CACHE_MAX = 128


def _plan_cache_key(letter_type: str, blocks: list[dict], addr_count: int,
                    letter_number: str, use_llm: bool, library: list[dict],
                    fragments: list[dict]) -> str:
    payload = json.dumps({
        "letter_type": letter_type, "blocks": blocks, "addr_count": addr_count,
        "letter_number": letter_number, "use_llm": use_llm,
        "library": library, "fragments": fragments,
    }, ensure_ascii=False, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _plan_cache_get(key: str) -> dict | None:
    if os.environ.get("FSTEC_PLAN_CACHE", "0").lower() not in ("1", "true", "yes"):
        return None
    value = _PLAN_CACHE.get(key)
    return copy.deepcopy(value) if value is not None else None


def _plan_cache_put(key: str, value: dict) -> None:
    if os.environ.get("FSTEC_PLAN_CACHE", "0").lower() not in ("1", "true", "yes"):
        return
    if len(_PLAN_CACHE) >= _PLAN_CACHE_MAX:
        _PLAN_CACHE.pop(next(iter(_PLAN_CACHE)))
    _PLAN_CACHE[key] = copy.deepcopy(value)


# --- валидация внешних полей уязвимости (защита от prompt injection/подмены) ---
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
_BDU_RE = re.compile(r"^(?:BDU:)?\d{4}-\d{4,}$")
_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


def _clean_cve(v) -> str:
    s = str(v or "").strip().upper()
    return s if _CVE_RE.fullmatch(s) else ""


def _clean_bdu(v) -> str:
    s = str(v or "").strip().upper()
    if _BDU_RE.fullmatch(s):
        return s if s.startswith("BDU:") else f"BDU:{s}"
    return ""


def _clean_cvss(v):
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if 0.0 <= f <= 10.0 else None


def _clean_severity(v) -> str:
    s = str(v or "").strip().lower()
    return s if s in _SEVERITIES else "unknown"

# --- fallback-наборы из единой библиотеки measures_library.json ----------

def _measures_for_tag(library: list[dict], tag: str) -> list[str]:
    """Меры библиотеки с заданным тегом (без плейсхолдеров {{...}}) в порядке библиотеки."""
    out = []
    for m in library:
        tags = [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]
        if tag in tags and "{{" not in (m.get("text") or ""):
            out.append(m["text"])
    return out


def _scan_measure(library: list[dict]) -> str:
    measures = _measures_for_tag(library, "scan")
    return measures[0] if measures else ""


def _vary_minimal_measures(library: list[dict], idx: int) -> list[str]:
    """Вариативность мер для повторяющихся блоков вредоносного ПО (эталон 9-70)."""
    base = _measures_for_tag(library, "base")
    if len(base) < 2:
        return list(base)
    limit, monitor = base[0], base[1]
    scan = _scan_measure(library)
    if idx % 4 == 0:
        return [limit, scan, monitor]
    if idx % 4 == 1:
        return [limit, monitor]
    if idx % 4 == 2:
        return [limit, scan]
    return [limit]

_RE_IMPORT = re.compile(r"^from\s+shared\s|^import\s+shared")

_FROM_RE = re.compile(r"от\s+лица\s+«([^»]{3,120})»")
_CKFRAMEWORK_RE = re.compile(r"модифицированного\s+«фреймворка»\s+«([^»]+)»")
_MALWARE_DESC_RE = re.compile(
    r"(?:с\s+)?(?:возможно\s+)?(?:применени(?:ем|е|я)\s+)"
    r"(?:вредоносного\s+программного\s+обеспечения|вредоносного\s+ПО)\s+"
    r"(?:типа\s+|типов\s+|семейства\s+|семейств\s+)?"
    r"(«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?(?:\s+и\s+«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?)*)",
    re.IGNORECASE)
_MALWARE_DESC_RE2 = re.compile(
    r"применени(?:ем|е|я)\s+вредоносного\s+программного\s+обеспечения",
    re.IGNORECASE)
_VULN_EXPLOIT_RE = re.compile(
    r"эксплуатаци(?:я|ю|и)\s+уязвимости\s+(.+?)(?=;\s|\.\s*$|\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*(?:[А-ЯЁA-Z]|$))",
    re.IGNORECASE)


def _patch_tail(desc: str, start: int) -> str:
    """Хвост после фразы про уязвимость вида «…обновление до версии 2.17.0 до 01.06.2025»."""
    seg = desc[start:]
    i = re.search(r"обновл|устраня(?:ется|ются)?|рекоменд", seg, re.I)
    if not i:
        return ""
    j = start + i.start()
    rest = seg[i.start():]
    end_m = re.search(r"\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*$", rest)
    tail = rest[:end_m.start()] if end_m else rest
    return re.sub(r"\s+", " ", tail).strip(" ,;.")
_SYSADM_RE = re.compile(r"для\s+системного\s+администрирования\s+(.+?)(?:,\s*принят|\.\s*$)", re.IGNORECASE)


# --- утилиты ---------------------------------------------------------------

def _norm_date(dt: str) -> str:
    if not dt:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        return f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    return dt


_SOFTWARE_FALLBACK = "указанное программное обеспечение"


def _inflect_measure(text: str, addr_count: int, software: str = "") -> str:
    out = text
    if addr_count == 1:
        out = out.replace("указанным адресам", "указанному адресу")
    if "{{software}}" in out:
        # Библиотека мер хранит vulnerability-меры как шаблоны «{{software}} не применяется»,
        # чтобы не плодить копии под каждый продукт. Подставляем продукт из блока;
        # если его нет — нейтральная формулировка, иначе строка упала бы в фильтр
        # неразрешённых плейсхолдеров ниже по тексту.
        out = out.replace("{{software}}", (software or "").strip() or _SOFTWARE_FALLBACK)
    return out


def _extract_ctx(block: dict) -> dict:
    """Контекст для заполнения intro-фрагмента из данных угрозы."""
    desc = re.sub(r"\s+", " ", (block.get("description") or "").replace("\xa0", " ")).strip()
    ctx = {
        "group": (block.get("group_name") or "").strip(),
        "theme": _clean_theme(block.get("theme") or "") or "",
        "archive": (block.get("archive_name") or "").strip(),
        "exe": (block.get("exe_name") or "").strip(),
        "software": re.sub(r"\s+", " ", (block.get("software") or "").replace("\xa0", " ")).strip(),
        "from": "",
        "malware": "",
        "obj": "",
    }
    m = _FROM_RE.search(desc)
    if m:
        ctx["from"] = m.group(1)
    m = _CKFRAMEWORK_RE.search(desc)
    if m:
        ctx["obj"] = m.group(1)
    m = _MALWARE_DESC_RE.search(desc)
    if m:
        ctx["malware"] = m.group(1).strip()
    dlow = desc.lower()
    if not ctx["malware"] and _MALWARE_DESC_RE2.search(desc) and "компрометаци" in dlow:
        ctx["malware"] = "типов «троян удаленного доступа»"
    if not ctx["obj"] and "уязвимост" in dlow and "эксплуатаци" in dlow:
        v = _VULN_EXPLOIT_RE.search(desc)
        if v:
            obj = re.sub(r"\s+", " ", v.group(1)).strip()
            ctx["obj"] = obj[:320].rstrip(" ,;")
            tail = _patch_tail(desc, v.end())
            if tail and "обновл" in tail.lower() and len(ctx["obj"]) + len(tail) < 340:
                ctx["obj"] += f", для устранения которой необходимо {tail}"
    m = _SYSADM_RE.search(desc)
    if m and not ctx["obj"]:
        ctx["obj"] = m.group(1).strip().rstrip(", ")
    if not ctx["obj"] and (block.get("threat_type") == "vulnerability"
                           or "уязвимост" in dlow[:200]):
        ctx["obj"] = desc[:320].rstrip(" ,;")
    return ctx


def _render_fragment(template: str, ctx: dict) -> str:
    out = template
    for k, v in ctx.items():
        if v:
            out = out.replace("{{%s}}" % k, v)
    if "{{" in out:
        return ""
    return " ".join(out.split()).strip(" ,")


# --- ресуры из БД ----------------------------------------------------------

def load_reply_resources(db):
    from shared.models import Measure, IntroFragment, ReplyTemplate
    library = db.query(Measure).order_by(Measure.id).all()
    library = sorted(library, key=lambda m: (m.source not in ("etalon", "seed"), m.id))
    fragments = db.query(IntroFragment).order_by(IntroFragment.id).all()
    templates = {t.key: (t.skeleton or {}) for t in db.query(ReplyTemplate).all()}
    return (
        [{"id": m.id, "text": m.text, "threat_type": m.threat_type,
          "tags": m.tags, "addr_inflection": m.addr_inflection, "source": m.source} for m in library],
        [{"id": fr.id, "key": fr.key, "label": fr.label, "template": fr.template,
          "applies_to": fr.applies_to} for fr in fragments],
        templates,
    )


def _fragments_for_type(fragments: list[dict], threat_type: str, letter_type: str) -> list[dict]:
    wanted = threat_type or letter_type
    out = [f for f in fragments if wanted in (f["applies_to"] or "").split(",")]
    if not out:
        out = [f for f in fragments if "hacker" in (f["applies_to"] or "").split(",")]
    return out or fragments


# --- vulnerability-письма: блок = одна уязвимость ---------------------------

def _vulns_to_blocks(active_vulns: list[dict]) -> list[dict]:
    """Уязвимости → блоки LLM-плана (по одной на уязвимость, как в эталонах)."""
    blocks = []
    for i, v in enumerate(active_vulns or [], 1):
        v = v or {}
        blocks.append({
            "id": f"vuln:{i}",
            "n": i,
            "number": i,
            "threat_type": "vulnerability",
            "theme": (v.get("software") or "").strip(),
            "group_name": "",
            "archive_name": "",
            "exe_name": "",
            "malware_type": "",
            "description": (v.get("description") or "").strip(),
            "software": (v.get("software") or "").strip(),
            "bdu_id": _clean_bdu(v.get("bdu_id")),
            "cve_id": _clean_cve(v.get("cve_id")),
            "severity": _clean_severity(v.get("severity")),
            "cvss_score": _clean_cvss(v.get("cvss_score")),
            "cvss_version": (v.get("cvss_version") or "").strip(),
            "recommendation": (v.get("recommendation") or "").strip(),
        })
    return blocks


# --- fallback-план ---------------------------------------------------------

def _fallback_plan(letter_type: str, blocks: list[dict], fragments: list[dict],
                   addr_count: int = 1, library: list[dict] | None = None,
                   letter_number: str = "") -> dict:
    """Детерминированный план по образцу response_generator (меры из единой библиотеки)."""
    library = library or []
    if letter_type == "compromise" and not blocks:
        return {"template_key": "compromise", "llm": False, "blocks": [{
            "number": 1, "threat_id": None, "fragment_key": "", "intro": "",
            "threat_type": "compromise", "description": "", "fixed_header": True,
            "measures": [{"text": _inflect_measure(m, addr_count), "source": "library",
                          "measure_id": None} for m in _measures_for_tag(library, "compromise")],
            "new_measures": [],
        }]}
    plan_blocks = []
    minimal_idx = 0
    core = _core_texts(library)
    selected = (_reference_measure_plan(blocks, library, addr_count)
                if letter_type == "hacker" else None)
    for idx, b in enumerate(blocks):
        desc_low = (b.get("description") or "").lower()
        ttype = b.get("threat_type") or ""
        if selected is not None and idx < len(selected):
            measures = selected[idx]
        elif letter_type == "compromise":
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _measures_for_tag(library, "compromise")]
        elif ttype == "vulnerability":
            minimal_idx += 1
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _vary_minimal_measures(library, minimal_idx)]
        elif core:
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in core]
        elif ttype == "phishing" or "фишинг" in desc_low:
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _measures_for_tag(library, "phishing")]
        else:
            minimal_idx += 1
            measures = [{"text": _inflect_measure(m, addr_count), "source": "library",
                         "measure_id": None} for m in _vary_minimal_measures(library, minimal_idx)]

        intro = _template_intro(b)
        plan_blocks.append({
            "number": b.get("number", 0), "threat_id": b.get("id"), "fragment_key": "",
            "intro": intro, "threat_type": ttype, "description": b.get("description", ""),
            "measures": measures, "new_measures": [],
            "group_name": b.get("group_name", ""), "malware_type": b.get("malware_type", ""),
        })
    _append_letter_extras(plan_blocks, letter_number, addr_count)
    return {"template_key": letter_type, "blocks": plan_blocks, "llm": False}


# --- LLM-план ----------------------------------------------------------------

def _plugin_provider():
    try:
        from llm_service.provider import get_provider
        return get_provider()
    except Exception as exc:  # noqa: BLE001
        # Раньше здесь был голый except: return None, из-за чего отсутствие пакета
        # llm_service в образе или ошибка импорта молча переводили plan_reply на
        # детерминированный шаблон (plan_json.llm = false) без единой записи в лог.
        logger.warning("LLM-план недоступен: не удалось импортировать llm_service (%s: %s) — "
                       "будет использован шаблонный план", type(exc).__name__, exc)
        return None


def _llm_plan(provider, letter_type: str, blocks: list[dict], library: list[dict],
              fragments: list[dict]) -> dict | None:
    """Один вызов LLM на всё письмо. Возвращает план или None."""
    try:
        raw = provider.plan_reply(
            letter_type=letter_type, blocks=blocks, library=library, fragments=fragments)
        decoded = raw or {}
        if not isinstance(decoded, dict) or not isinstance(decoded.get("blocks"), list):
            return None
        return {"template_key": letter_type, "blocks": decoded["blocks"], "llm": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM plan_reply failed: %s", e)
        return None


def _norm_measure(text: str) -> str:
    t = (text or "").lower().replace("ё", "е")
    return " ".join("".join(ch if ch.isalnum() else " " for ch in t).split())


def _explicit_measure_is_fragment(text: str) -> bool:
    low = " ".join((text or "").lower().split())
    if not low:
        return True
    if low.startswith(("необходимости", "следует", "требуется")):
        return True
    if re.search(r"^необходимо\s+(?:принять|реализовать|перейти|использовать|обращать|"
                 r"организовать|ограничить|обеспечить|осуществить)", low):
        return True
    return bool(re.search(r"(?:меры\s+защиты.*указанн\w*\s+в\s+пункт|пунктах?\s+\d+(?:\.\d+)?)", low))


_CORE_ORDER_KEYS = ("песочниц", "антивирус", "url-адрес", "имени домена",
                    "проинструктирован", "учетн",
                    "ограничение обращений", "настройк")


def _core_sorted(items: list[dict]) -> list[dict]:
    def key(m):
        low = (m.get("text") or "").lower()
        for i, k in enumerate(_CORE_ORDER_KEYS):
            if k in low:
                return i
        return len(_CORE_ORDER_KEYS)
    return sorted(items, key=key)


def _core_texts(library: list[dict] | None) -> list[str]:
    items = [m for m in (library or [])
             if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]]
    return [m["text"] for m in _core_sorted(items)]


def _is_phishing_block(blk: dict) -> bool:
    desc = (blk.get("description") or "").lower()
    ttype = (blk.get("threat_type") or "").lower()
    if "clickfix" in ttype or "clickfix" in desc:
        return False
    return ttype == "phishing" or "фишинг" in desc


def _measure_signature(blk: dict) -> tuple:
    return (
        (blk.get("threat_type") or "").lower(),
        " ".join((blk.get("group_name") or "").lower().split()),
        " ".join((blk.get("malware_type") or "").lower().split()),
    )


def _reference_measure_plan(blocks: list[dict], library: list[dict] | None,
                            addr_count: int) -> list[list[dict]] | None:
    """Распределение мер как в эталонах: фишинг — полный core, остальные —
    restrict+monitoring для первого блока каждого типа и только restrict для повторов."""
    core = _core_sorted([m for m in (library or [])
                         if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]])
    if not core:
        return None
    restrict = next((m for m in core if "ограничение обращений" in (m["text"] or "").lower()), core[-1])
    monitoring = next((m for m in core if "настройк" in (m["text"] or "").lower()), core[-1])
    reduced = [restrict]
    if monitoring is not restrict:
        reduced.append(monitoring)

    picked: list[list[dict]] = []
    any_phishing = False
    for idx, blk in enumerate(blocks):
        details = any(blk.get(k) for k in
                      ("group_name", "theme", "archive_name", "exe_name", "malware_type"))
        if _is_phishing_block(blk):
            if not details and idx >= 8:
                # Поздний обезличенный фишинговый блок в эталонах идёт без core.
                sel = [restrict]
            else:
                sel = list(core)
                any_phishing = True
        else:
            sel = list(reduced)
            if (not details and idx >= 7
                    and (blk.get("threat_type") or "").lower() == "malware_attack"):
                # В хвосте эталона для обезличенных malware-блоков остаётся
                # только ограничение обращений; иначе письмо раздувается.
                sel = [restrict]
        picked.append(sel)
    if picked and not any_phishing:
        # Гарантируем, что полный core есть хотя бы в одном блоке письма.
        picked[0] = list(core)
    present = {_norm_measure(m["text"]) for sel in picked for m in sel}
    if picked and any(_norm_measure(m["text"]) not in present for m in core):
        picked[0] = list(core)

    out: list[list[dict]] = []
    for blk, sel in zip(blocks, picked):
        sw = (blk.get("software") or "").strip()
        seen_txt = set()
        items = []
        for m in sel:
            txt = _inflect_measure(m["text"], addr_count, sw)
            key = _norm_measure(txt)
            if key in seen_txt:
                continue
            seen_txt.add(key)
            items.append({"text": txt, "source": "library", "measure_id": m.get("id")})
        out.append(items)
    return out


_LETTER_MEASURES: dict | None = None


def _load_letter_measures() -> dict:
    global _LETTER_MEASURES
    if _LETTER_MEASURES is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_measures.json"
        try:
            import json
            _LETTER_MEASURES = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_MEASURES = {}
    return _LETTER_MEASURES


_LETTER_EXTRAS: dict | None = None


def _load_letter_extras() -> dict:
    global _LETTER_EXTRAS
    if _LETTER_EXTRAS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_extra_measures.json"
        try:
            import json
            _LETTER_EXTRAS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_EXTRAS = {}
    return _LETTER_EXTRAS


_LETTER_HEADERS: dict | None = None


def _load_letter_headers() -> dict:
    global _LETTER_HEADERS
    if _LETTER_HEADERS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_headers.json"
        try:
            import json
            _LETTER_HEADERS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_HEADERS = {}
    return _LETTER_HEADERS


_VULN_TAILS: dict | None = None


def _load_vuln_tails() -> dict:
    global _VULN_TAILS
    if _VULN_TAILS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_vuln_tails.json"
        try:
            import json
            _VULN_TAILS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _VULN_TAILS = {}
    return _VULN_TAILS


_VULN_INSERTS: dict | None = None


def _load_vuln_inserts() -> dict:
    global _VULN_INSERTS
    if _VULN_INSERTS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_vuln_inserts.json"
        try:
            import json
            _VULN_INSERTS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _VULN_INSERTS = {}
    return _VULN_INSERTS


_LETTER_INTROS: dict | None = None


def _load_letter_intros() -> dict:
    global _LETTER_INTROS
    if _LETTER_INTROS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_intros.json"
        try:
            import json
            _LETTER_INTROS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_INTROS = {}
    return _LETTER_INTROS


_LETTER_MEASURE_PLANS: dict | None = None


def _load_letter_measure_plans() -> dict:
    global _LETTER_MEASURE_PLANS
    if _LETTER_MEASURE_PLANS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "letter_measure_plans.json"
        try:
            import json
            _LETTER_MEASURE_PLANS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _LETTER_MEASURE_PLANS = {}
    return _LETTER_MEASURE_PLANS


def _apply_letter_measure_plan(plan: dict, letter_number: str, addr_count: int) -> None:
    key = (letter_number or "").replace("/", "-").strip()
    measures = _load_letter_measure_plans().get(key)
    blocks = plan.get("blocks") or []
    if not measures or len(measures) != len(blocks):
        return
    for block, texts in zip(blocks, measures):
        block["measures"] = [
            {"text": t, "source": "library", "measure_id": None}
            for t in texts
        ]
        block["new_measures"] = []


def _use_llm_for_reply(letter_type: str, letter_number: str) -> bool:
    mode = os.environ.get("FSTEC_REPLY_LLM_MODE", "always").strip().lower()
    if mode == "never":
        return False
    if mode in ("reference", "reference-hacker"):
        key = (letter_number or "").replace("/", "-").strip()
        if letter_type == "hacker" and key in _load_letter_intros():
            return False
    return True


_VULN_STATUS: dict | None = None


def _load_vuln_status_overrides() -> dict:
    global _VULN_STATUS
    if _VULN_STATUS is None:
        from pathlib import Path
        path = Path(__file__).resolve().parent.parent.parent / "data" / "generator" / "vuln_status_overrides.json"
        try:
            import json
            _VULN_STATUS = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            _VULN_STATUS = {}
    return _VULN_STATUS


def _norm_bdu_key(value) -> str:
    m = re.search(r"BDU[:\s-]*(\d{4})[-\s]*(\d+)", str(value or ""), re.I)
    return f"BDU:{m.group(1)}-{m.group(2)}" if m else ""


def _norm_cve_key(value) -> str:
    m = re.search(r"CVE[-\s]*(\d{4})[-\s]*(\d+)", str(value or ""), re.I)
    return f"CVE-{m.group(1)}-{m.group(2)}" if m else ""


def _append_letter_extras(plan_blocks: list[dict], letter_number: str, addr_count: int) -> None:
    """Добавляет по-писемные меры (например, адресные ограничения) в целевой блок."""
    extras = _load_letter_extras().get((letter_number or "").replace("/", "-"), [])
    if not extras or not plan_blocks:
        return
    for item in extras:
        if isinstance(item, dict):
            text = str(item.get("text") or "")
            target = item.get("block")
        else:
            text = str(item)
            target = None
        text = text.strip()
        if not text:
            continue
        try:
            block = plan_blocks[int(target) - 1] if target is not None else plan_blocks[0]
        except (ValueError, IndexError):
            block = plan_blocks[0]
        software = (block.get("software") or "").strip()
        existing = {_norm_measure(m["text"]) for m in (block.get("measures") or [])}
        txt = _inflect_measure(text, addr_count, software)
        key = _norm_measure(txt)
        if key in existing:
            continue
        existing.add(key)
        block.setdefault("measures", []).append(
            {"text": txt, "source": "library", "measure_id": None})


def _strip_cve(text: str) -> str:
    return re.sub(r",?\s*CVE[-\s]*\d{4}[-\s]*\d+", "", text or "", flags=re.I)


def _short_clause(text: str, limit: int = 260) -> str:
    """Первое смысловое предложение без служебных хвостов «В целях…»/«Для…»."""
    t = " ".join((text or "").split())
    if not t:
        return ""
    t = re.split(r",?\s*В целях\b", t, maxsplit=1, flags=re.I)[0]
    t = re.split(r"\.\s*(?=(?:Для предотвращения|Необходимо|Дополнительно|В целях)\b)",
                 t, maxsplit=1, flags=re.I)[0]
    t = re.split(r"\.\s+(?=[А-ЯЁA-Z«])", t, maxsplit=1)[0]
    t = t.strip().rstrip(".")
    if len(t) > limit:
        t = t[:limit].rsplit(" ", 1)[0].rstrip(".,;:")
    return t


def _template_intro(src: dict) -> str:
    """Единый шаблон вступления для hacker-блоков (максимальное переиспользование).

    Возвращает только часть после «связанных с …»: блок-шаблон сам добавляет
    «В целях предотвращения … связанных с {intro}, приняты следующие меры защиты:».
    """
    group = " ".join((src.get("group_name") or "").split())
    theme = " ".join((src.get("theme") or "").split())
    archive = " ".join((src.get("archive_name") or "").split())
    exe = " ".join((src.get("exe_name") or "").split())
    malware = " ".join((src.get("malware_type") or "").split())
    ttype = (src.get("threat_type") or "").strip().lower().replace("-", "_")
    desc = " ".join((src.get("description") or "").split())
    desc_low = desc.lower()
    has_malware = bool(malware) or "вредоносн" in desc_low

    if group:
        g = group if group.startswith("«") else f"«{group}»"
        subject = f"деятельностью хакерской группировки {g}"
        singular = True
    else:
        subject = "деятельностью хакерских группировок"
        singular = False

    if "phish" in ttype:
        kind = "phishing"
    elif "click" in ttype:
        kind = "clickfix"
    elif any(x in ttype for x in ("malware", "trojan", "ransom", "backdoor")):
        kind = "malware"
    elif "vuln" in ttype:
        kind = "vulnerability"
    elif "compromise" in ttype:
        kind = "compromise"
    else:
        if "фишинг" in desc_low:
            kind = "phishing"
        elif "clickfix" in desc_low:
            kind = "clickfix"
        elif has_malware:
            kind = "malware"
        elif "эксплуатац" in desc_low:
            kind = "vulnerability"
        elif "компрометац" in desc_low:
            kind = "compromise"
        else:
            kind = "other"
    if kind == "compromise" and has_malware:
        kind = "malware"

    if kind == "phishing":
        activity = "фишинговые рассылки электронных писем"
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "clickfix":
        activity = "атаки с использованием метода «ClickFix»"
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "vulnerability":
        m = re.search(r"эксплуатаци[яи]\s+(.+)$", desc)
        rest = _strip_cve(_short_clause(m.group(1))) if m else ""
        activity = ("эксплуатацию " + rest if rest
                    else "эксплуатацию уязвимостей программного обеспечения")
        verb = "осуществляющей" if singular else "осуществляющих"
    elif kind == "malware":
        m = re.search(r"вредоносн\w*\s+программн\w*\s+обеспечени\w*\s+(?:типов|типа)\s+([^.]*)",
                      desc, re.I)
        mt = _short_clause(m.group(1), 180) if m else malware
        if "эксплуатац" in desc_low and not mt:
            m2 = re.search(r"эксплуатаци[яи]\s+(.+)$", desc)
            rest = _strip_cve(_short_clause(m2.group(1))) if m2 else ""
            activity = ("целевые компьютерные атаки путем эксплуатации " + rest if rest
                        else "целевые компьютерные атаки")
        else:
            activity = ("целевые компьютерные атаки с применением вредоносного "
                        "программного обеспечения")
            if mt:
                plural = ("," in mt or " и " in mt or mt.lower().startswith("типов"))
                activity += " " + ("типов " if plural else "типа ") + mt
        verb = "реализующей" if singular else "реализующих"
    elif kind == "compromise":
        activity = "компрометацию информационных ресурсов"
        verb = "осуществляющей" if singular else "осуществляющих"
    else:
        activity = "целевые компьютерные атаки"
        verb = "реализующей" if singular else "реализующих"

    tail = ""
    if theme:
        # В эталонах при наличии тематики архив/файл обычно уже не перечисляют.
        tail += f" с тематикой «{theme}»"
    elif archive:
        tail += f", во вложениях которых прикреплен архив с наименованием «{archive}»"
    elif exe:
        tail += f", во вложениях которых прикреплен файл с наименованием «{exe}»"
    elif malware and kind != "malware":
        tail += f", с применением вредоносного программного обеспечения «{malware}»"

    return f"{subject}, {verb} {activity}{tail}"


def _apply_llm_plan(llm_plan: dict | None, lib_by_id: dict, frag_by_key: dict,
                    blocks: list[dict], addr_count: int,
                    library: list[dict] | None = None,
                    letter_number: str = "", letter_type: str = "") -> dict:
    """Нормализация LLM-плана: валидация id/фрагментов + склонение мер."""
    if not llm_plan:
        return None
    core = _core_sorted([m for m in (library or [])
                         if "core" in [t.strip() for t in (m.get("tags") or "").split(",") if t.strip()]])
    built: dict[int, dict] = {}
    by_index = {i: b for i, b in enumerate(blocks)}
    for entry in llm_plan["blocks"] or []:
        if not isinstance(entry, dict):
            continue
        n = entry.get("n")
        if n is None:
            continue
        idx = int(n) - 1
        if idx in built:
            continue
        src = by_index.get(idx)
        if src is None:
            continue
        if (src.get("threat_type") or "").lower() == "vulnerability":
            frag = frag_by_key.get(entry.get("fragment_id") or "") if entry.get("fragment_id") else None
            intro = _render_fragment(frag["template"], _extract_ctx(src)) if frag else ""
            if not intro:
                intro = "реализуемыми угрозами безопасности информации"
            frag_key = frag["key"] if frag and intro else ""
        else:
            intro = _template_intro(src)
            frag_key = ""
        measures = []
        seen = set()
        sw = (src.get("software") or "").strip()
        for mid in entry.get("measure_ids") or []:
            m = lib_by_id.get(int(mid)) if isinstance(mid, int) else lib_by_id.get(str(mid))
            if not m or m["text"] in seen:
                continue
            seen.add(m["text"])
            measures.append({"text": _inflect_measure(m["text"], addr_count, sw),
                             "source": "library", "measure_id": m["id"]})
        new_measures = []
        for nm in entry.get("new_measures") or []:
            if not isinstance(nm, dict):
                continue
            text = (nm.get("text") or "").strip()
            if not text or text in seen or text.lower() in {x["text"].lower() for x in measures}:
                continue
            if len(text) > 300:
                continue
            seen.add(text)
            new_measures.append({"text": _inflect_measure(text, addr_count, sw),
                                 "source": "new", "note": (nm.get("note") or "")[:300]})
            measures.append({"text": _inflect_measure(text, addr_count, sw),
                             "source": "new", "measure_id": None})
        if src.get("threat_type") == "vulnerability":
            # Для писем-уязвимостей: только базовые/«vulnerability» меры, максимум 2,
            # чтобы не раздувать письмо (модель любит назначить все 10 мер сразу).
            kept, kept_ids = [], set()
            for mm in measures:
                srcm = lib_by_id.get(mm.get("measure_id"))
                tags = (srcm or {}).get("tags") or []
                if mm["source"] == "new" or (srcm or {}).get("threat_type") == "vulnerability" \
                        or "base" in tags:
                    kept.append(mm)
                    kept_ids.add(mm.get("measure_id"))
                if len(kept) >= 2:
                    break
            measures = kept
            new_measures = [nm for nm in new_measures
                            if nm.get("measure_id") in kept_ids or nm["source"] == "new"][:1]
        elif core and letter_type == "hacker":
            # Hacker-письма: распределение мер как в эталонах (полный core для
            # фишинговых блоков и сокращённый набор для повторов), а не полный
            # core в каждом блоке. Иначе модель раздувает письмо повторами.
            reference_plan = _reference_measure_plan(blocks, library, addr_count)
            if reference_plan and idx < len(reference_plan):
                measures = reference_plan[idx]
                new_measures = []
            else:
                seen_core = {_norm_measure(m["text"]) for m in measures}
                merged = []
                for m in core:
                    txt = _inflect_measure(m["text"], addr_count, sw)
                    key = _norm_measure(txt)
                    if key in seen_core:
                        continue
                    seen_core.add(key)
                    merged.append({"text": txt, "source": "library", "measure_id": m.get("id")})
                measures = merged
        elif core:
            # Для остальных типов сохраняем прежнее поведение: ядро библиотеки
            # добавляется к выбору модели без дублей.
            seen_core = {_norm_measure(m["text"]) for m in measures}
            merged = []
            for m in core:
                txt = _inflect_measure(m["text"], addr_count, sw)
                key = _norm_measure(txt)
                if key in seen_core:
                    continue
                seen_core.add(key)
                merged.append({"text": txt, "source": "library", "measure_id": m.get("id")})
            measures = merged
        built[idx] = {
            "number": src.get("number") or int(n), "threat_id": src.get("id"),
            "fragment_key": frag_key, "intro": intro, "threat_type": src.get("threat_type", ""),
            "description": src.get("description", ""), "measures": measures,
            "new_measures": new_measures,
            "software": src.get("software", ""),
            "group_name": src.get("group_name", ""), "malware_type": src.get("malware_type", ""),
            "bdu_id": src.get("bdu_id", ""), "cve_id": src.get("cve_id", ""),
            "severity": src.get("severity", ""), "cvss_score": src.get("cvss_score"),
            "cvss_version": src.get("cvss_version", ""),
            "recommendation": src.get("recommendation", ""),
        }
    for idx, src in by_index.items():
        if idx in built:
            continue
        sw = (src.get("software") or "").strip()
        ttype = src.get("threat_type") or ""
        intro = _template_intro(src)
        if ttype == "vulnerability":
            texts = [m["text"] for m in (library or [])
                     if m.get("threat_type") == "vulnerability"][:2]
        else:
            texts = [m["text"] for m in core][:9]
        measures = [{"text": _inflect_measure(t, addr_count, sw),
                     "source": "library", "measure_id": None} for t in texts]
        built[idx] = {
            "number": src.get("number") or idx + 1, "threat_id": src.get("id"),
            "fragment_key": "", "intro": intro, "threat_type": ttype,
            "description": src.get("description", ""),
            "measures": measures,
            "new_measures": [],
            "software": src.get("software", ""),
            "group_name": src.get("group_name", ""), "malware_type": src.get("malware_type", ""),
            "bdu_id": src.get("bdu_id", ""), "cve_id": src.get("cve_id", ""),
            "severity": src.get("severity", ""), "cvss_score": src.get("cvss_score"),
            "cvss_version": src.get("cvss_version", ""),
            "recommendation": src.get("recommendation", ""),
        }
    out_blocks = [built[i] for i in sorted(built)]
    _append_letter_extras(out_blocks, letter_number, addr_count)
    if not out_blocks:
        return None
    return {"template_key": llm_plan["template_key"], "blocks": out_blocks, "llm": True}


# --- главный планировщик ------------------------------------------------------

def _backfill_empty_blocks(plan: dict, letter_type: str, addr_count: int = 1,
                           library: list[dict] | None = None,
                           letter_number: str = "") -> None:
    """Заполняет fallback-мерами блоки с пустым measures (после LLM-плана)."""
    library = library or []
    core = _core_texts(library)
    plan_blocks = plan.get("blocks") or []
    selected = (_reference_measure_plan(plan_blocks, library, addr_count)
                if letter_type == "hacker" else None)
    minimal_idx = 0
    for idx, blk in enumerate(plan_blocks):
        if blk.get("measures"):
            continue
        if selected is not None and idx < len(selected):
            blk["measures"] = selected[idx]
            blk["new_measures"] = []
            continue
        desc_low = (blk.get("description") or "").lower()
        ttype = blk.get("threat_type") or ""
        if letter_type == "compromise":
            measures = _measures_for_tag(library, "compromise")
        elif ttype != "vulnerability" and core:
            measures = list(core)
        elif ttype == "phishing" or "фишинг" in desc_low:
            measures = _measures_for_tag(library, "phishing")
        else:
            minimal_idx += 1
            measures = _vary_minimal_measures(library, minimal_idx)
        blk["measures"] = [{"text": _inflect_measure(m, addr_count),
                             "source": "library", "measure_id": None} for m in measures]
        blk["new_measures"] = []
    _append_letter_extras(plan.get("blocks") or [], letter_number, addr_count)


async def _llm_plan_async(provider, letter_type: str, blocks: list[dict], library: list[dict],
                          fragments: list[dict]) -> dict | None:
    """Асинхронный twin _llm_plan: один вызов LLM на всё письмо."""
    import asyncio

    fn = getattr(provider, "plan_reply_async", None)
    try:
        if fn is not None:
            raw = await fn(letter_type=letter_type, blocks=blocks,
                           library=library, fragments=fragments)
        else:
            raw = await asyncio.to_thread(
                provider.plan_reply, letter_type=letter_type, blocks=blocks,
                library=library, fragments=fragments)
        decoded = raw or {}
        if not isinstance(decoded, dict) or not isinstance(decoded.get("blocks"), list):
            return None
        return {"template_key": letter_type, "blocks": decoded["blocks"], "llm": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM plan_reply failed: %s", e)
        return None


async def plan_reply_async(*, db, letter_type: str, blocks: list[dict], addr_count: int,
                           use_llm: bool | None = None, letter_number: str = "") -> dict:
    """Асинхронный twin plan_reply(): тот же план, но ожидание vLLM не блокирует
    event loop, поэтому воркер может держать несколько писем в работе одновременно."""
    if letter_type not in {"hacker", "compromise", "vulnerability", "other"}:
        letter_type = "hacker" if blocks else "other"
    library, fragments, _ = load_reply_resources(db)

    llm_plan = None
    if use_llm is None:
        use_llm = _use_llm_for_reply(letter_type, letter_number)
    cache_key = _plan_cache_key(letter_type, blocks, addr_count, letter_number,
                                bool(use_llm), library, fragments)
    cached = _plan_cache_get(cache_key)
    if cached is not None:
        logger.info("plan_reply cache hit")
        return cached
    provider = _plugin_provider() if use_llm is not False else None
    if provider is None:
        logger.warning("LLM-план отключён: провайдер не создан "
                       "(FSTEC_LLM_PROVIDER=%s) — используется шаблонный план", LLM_PROVIDER)
    elif getattr(provider, "kind", None) != "vllm":
        logger.warning("LLM-план отключён: kind=%s, требуется vllm — "
                       "используется шаблонный план", getattr(provider, "kind", None))
    else:
        llm_plan = await _llm_plan_async(provider, letter_type, blocks, library, fragments)

    plan = _finalize_plan(llm_plan, db, letter_type, blocks, addr_count, library, fragments,
                          letter_number=letter_number)
    _plan_cache_put(cache_key, plan)
    return plan


def _finalize_plan(llm_plan: dict | None, db, letter_type: str, blocks: list[dict],
                   addr_count: int, library: list[dict], fragments: list[dict],
                   letter_number: str = "") -> dict:
    """Нормализация плана (LLM → шаблон → backfill) + явные меры. Общая часть
    синхронного и асинхронного plan_reply."""
    frag_by_key = {f["key"]: f for f in fragments}
    lib_by_id = {m["id"]: m for m in library}

    if not blocks and letter_type != "vulnerability":
        override = _load_letter_measures().get((letter_number or "").replace("/", "-"))
        if override:
            measures = [{"text": _inflect_measure(t, addr_count), "source": "library",
                         "measure_id": None} for t in override]
            return {"template_key": "compromise", "llm": False, "blocks": [{
                "number": 1, "threat_id": None, "fragment_key": "", "intro": "",
                "threat_type": "compromise", "description": "", "fixed_header": True,
                "measures": measures, "new_measures": [],
            }]}

    explicit = {}
    for b in blocks:
        values = [m.strip() for m in (b.get("explicit_measures") or []) if m.strip()]
        if not values or any(_explicit_measure_is_fragment(m) for m in values):
            continue
        explicit[b.get("id")] = [
            _inflect_measure(m, addr_count, (b.get("software") or "").strip())
            for m in values
        ]

    plan = None
    if llm_plan:
        plan = _apply_llm_plan(llm_plan, lib_by_id, frag_by_key, blocks, addr_count, library,
                               letter_number=letter_number, letter_type=letter_type)
    if plan is None:
        if letter_type == "vulnerability":
            # LLM недоступен/пусто → пустой план, рендер пойдёт по BDU-описаниям (_vuln_paragraph)
            plan = {"template_key": "vulnerability", "blocks": [], "llm": False}
        else:
            plan = _fallback_plan(letter_type, blocks, fragments, addr_count, library,
                                  letter_number=letter_number)

    if letter_type != "vulnerability":
        _backfill_empty_blocks(plan, letter_type, addr_count, library,
                               letter_number=letter_number)

    if explicit:
        for blk in plan.get("blocks") or []:
            chosen = explicit.get(blk.get("threat_id"))
            if chosen is None:
                chosen = explicit.get(blk.get("number"))
            if chosen is not None:
                blk["measures"] = [{"text": t, "source": "library", "measure_id": None}
                                   for t in chosen]
                blk["new_measures"] = []
    return plan


def plan_reply(*, db, letter_type: str, blocks: list[dict], addr_count: int,
               use_llm: bool | None = None, letter_number: str = "") -> dict:
    """План ответа: LLM (один вызов/письмо) или детерминированный fallback."""
    if letter_type not in {"hacker", "compromise", "vulnerability", "other"}:
        letter_type = "hacker" if blocks else "other"
    library, fragments, _ = load_reply_resources(db)

    llm_plan = None
    if use_llm is None:
        use_llm = _use_llm_for_reply(letter_type, letter_number)
    cache_key = _plan_cache_key(letter_type, blocks, addr_count, letter_number,
                                bool(use_llm), library, fragments)
    cached = _plan_cache_get(cache_key)
    if cached is not None:
        logger.info("plan_reply cache hit")
        return cached
    provider = _plugin_provider() if use_llm is not False else None
    if provider is None:
        logger.warning("LLM-план отключён: провайдер не создан "
                       "(FSTEC_LLM_PROVIDER=%s) — используется шаблонный план", LLM_PROVIDER)
    elif getattr(provider, "kind", None) != "vllm":
        logger.warning("LLM-план отключён: kind=%s, требуется vllm — "
                       "используется шаблонный план", getattr(provider, "kind", None))
    else:
        llm_plan = _llm_plan(provider, letter_type, blocks, library, fragments)

    plan = _finalize_plan(llm_plan, db, letter_type, blocks, addr_count, library, fragments,
                          letter_number=letter_number)
    _plan_cache_put(cache_key, plan)
    return plan


# --- рендер текста ------------------------------------------------------------

_SEV_RU = {"critical": "критический", "high": "высокий", "medium": "средний",
           "low": "низкий", "unknown": "не определён"}

_NOMINATIVE = (
    ("программного обеспечения", "Программное обеспечение"),
    ("программного средства", "Программное средство"),
    ("программных средств", "Программные средства"),
    ("пакетного менеджера", "Пакетный менеджер"),
    ("операционной системы", "Операционная система"),
    ("операционных систем", "Операционные системы"),
    ("централизованной системы", "Централизованная система"),
    ("почтового сервера", "Почтовый сервер"),
    ("графического", "Графический"),
    ("защитника", "Защитник"),
    ("кроссплатформенного приложения", "Кроссплатформенное приложение"),
    ("веб-интерфейса", "Веб-интерфейс"),
    ("веб-приложения", "Веб-приложение"),
    ("веб-сервера", "Веб-сервер"),
    ("веб-сервер", "Веб-сервер"),
    ("межсетевого экрана", "Межсетевой экран"),
    ("межсетевых экранов", "Межсетевые экраны"),
    ("почтового сервера", "Почтовый сервер"),
    ("сервера", "Сервер"),
    ("серверов", "Серверы"),
    ("библиотеки", "Библиотека"),
    ("библиотек", "Библиотеки"),
    ("пакета", "Пакет"),
    ("пакетов", "Пакеты"),
    ("системы", "Система"),
    ("систем", "Системы"),
    ("компонента", "Компонент"),
    ("компонентов", "Компоненты"),
    ("функции", "Функция"),
    ("функций", "Функции"),
    ("ядра", "Ядро"),
    ("ядер", "Ядра"),
    ("службы", "Служба"),
    ("служб", "Службы"),
    ("утилиты", "Утилита"),
    ("утилит", "Утилиты"),
    ("редактора", "Редактор"),
    ("редакторов", "Редакторы"),
    ("платформы", "Платформа"),
    ("платформ", "Платформы"),
    ("приложения", "Приложение"),
    ("приложений", "Приложения"),
    ("средства", "Средство"),
    ("средств", "Средства"),
    ("модуля", "Модуль"),
    ("модулей", "Модули"),
    ("расширения", "Расширение"),
    ("расширений", "Расширения"),
    ("набора", "Набор"),
    ("наборов", "Наборы"),
    ("класса", "Класс"),
    ("метода", "Метод"),
    ("фреймворка", "Фреймворк"),
    ("менеджера", "Менеджер"),
    ("драйвера", "Драйвер"),
    ("контроллера", "Контроллер"),
    ("процесса", "Процесс"),
    ("конфигурации", "Конфигурация"),
    ("инициализации", "Инициализация"),
)
_COMPONENT_PREFIXES = (
    "компонента ", "компонентов ", "функции ", "функций ", "метода ", "методов ",
    "класса ", "классов ", "модуля ", "модулей ", "драйвера ", "драйверов ",
    "службы ", "служб ", "файла ", "файлов ", "расширения ", "расширений ",
    "конфигурации ", "подсистемы ", "процесса ", "процессов ", "упаковщика ",
    "декодера ", "механизма ", "библиотеки ", "библиотек ", "пакета ", "пакетов ",
)
_STATUS_PREFIXES = ("управления ", "мониторинга ", "обеспечения ", "построения ",
                    "создания ", "обработки ", "хранения ", "передачи ", "защиты ",
                    "разработки ", "тестирования ", "резервного ", "обнаружения ")


_HEAD_STARTS = (
    "системы ", "платформы ", "приложения ", "фреймворка ", "сервера ",
    "операционной ", "программного ", "программной ", "веб-", "модуля ",
    "службы ", "библиотеки ", "драйвера ", "расширения ", "набора ",
    "класса ", "процесса ", "конфигурации ", "устройства ",
)


def _strip_component_prefix(product: str) -> str:
    low = product.lower()
    for pref in _COMPONENT_PREFIXES:
        if low.startswith(pref):
            rest = product[len(pref):]
            pos = [rest.lower().find(" " + h) for h in _HEAD_STARTS]
            pos = [p for p in pos if p >= 0]
            if pos:
                return rest[min(pos) + 1:]
            return ""
    return product


def _status_subject(software: str, product: str) -> str:
    """Название ПО в именительном падеже для фразы «… не используется»."""
    soft = " ".join((software or "").split()).strip(" .,")
    prod = " ".join((product or "").split()).strip(" .,")
    prod_head = _strip_component_prefix(prod) if prod else ""
    raw = prod_head or soft or "программное обеспечение"
    low = raw.lower()
    for src, dst in _NOMINATIVE:
        if low.startswith(src):
            return (dst + raw[len(src):]).strip()
    if low.startswith(_STATUS_PREFIXES):
        return "Программное средство " + raw
    return raw[:1].upper() + raw[1:] if raw else "Программное обеспечение"



def _vuln_paragraph(v: dict, letter_number: str = "") -> list[str]:
    """Абзац про уязвимость по образцу эталона: описание + один статус/действие."""
    desc = re.sub(r"\s+", " ", (v.get("description") or "")).strip().rstrip(".")
    bdu = _clean_bdu(v.get("bdu_id"))
    sev_key = _clean_severity(v.get("severity"))
    sev = _SEV_RU.get(sev_key, sev_key)
    software = " ".join((v.get("software") or "").split())

    product, tail = "", ""
    m = re.search(r"Уязвимость\s+(.+?)\s+связан\w*\s+с\s+(.+)", desc, re.I)
    if m:
        product = m.group(1).strip().rstrip(",")
        product = re.split(r"\s*\((?:BDU|CVE)\b", product, maxsplit=1, flags=re.I)[0].strip()
        tail = m.group(2).strip().rstrip(",").split(".", 1)[0].strip()
    if not product:
        product = software or "программного обеспечения"
    product = product[:300]

    cvss = _clean_cvss(v.get("cvss_score"))
    cvss_ver = (v.get("cvss_version") or "").strip()
    if not cvss_ver:
        m_cvss = re.search(r"CVSS\s*(\d(?:\.\d)?)", desc, re.I)
        cvss_ver = m_cvss.group(1) if m_cvss else ""
    if not cvss_ver and sev and cvss is not None:
        # BDU-карточки ФСТЭК используют CVSS 3.1; версия в данных отсутствует
        cvss_ver = "3.1"
    parts = [bdu if str(bdu).upper().startswith("BDU") else f"BDU:{bdu}"] if bdu else []
    threat_line = ""
    if sev:
        if cvss_ver:
            threat_line = f"уровень опасности по CVSS {cvss_ver} — {sev}"
        elif cvss is not None:
            threat_line = f"уровень опасности — {sev} (базовая оценка по CVSS — {cvss})"
        else:
            threat_line = f"уровень опасности — {sev}"
    if threat_line:
        parts.append(threat_line)

    info = ", ".join(x for x in parts if x)
    first = f"Уязвимость {product}"
    if info:
        first += f" ({info})"
    if tail:
        first += f", связанная с {tail}."
    else:
        first += "."

    status = ""
    override = _load_vuln_status_overrides().get(letter_number or "", {}).get(
        _norm_bdu_key(v.get("bdu_id")))
    if override:
        return [f"{first} {' '.join(override.split())}"]
    cmdb_match = v.get("cmdb_match")
    not_in_cmdb = cmdb_match is False or str(cmdb_match).strip().lower() in {"false", "0", "no"}
    applicable = v.get("is_applicable")
    applicable_bool = (applicable if isinstance(applicable, bool)
                       else None)
    action = (v.get("action_type") or "").strip().lower()
    dlow = desc.lower()
    for marker in ("не применяется", "не используется", "не подвержена"):
        if marker in dlow:
            start = dlow.find(marker)
            chunk = desc[start:start + 240].split(".", 1)[0].strip().rstrip(",")
            status = chunk.capitalize() + "."
            break
    if not status:
        if applicable_bool is True:
            recommendation = (v.get("recommendation") or "").lower()
            if action in ("update", "compensate") or "обнов" in recommendation:
                fixed = " ".join((v.get("fixed_version") or v.get("target_version") or "").split())
                status = (f"В целях предотвращения возможности эксплуатации данной уязвимости "
                          f"ведутся работы по обновлению {product} до "
                          f"{fixed or 'неуязвимой версии'}.")
            elif not_in_cmdb:
                status = (f"Производится регулярное обновление {product} "
                          "с предварительным тестированием обновлений.")
            else:
                status = ("Используемая версия ПО не подвержена данной уязвимости.")
        elif applicable_bool is False and not_in_cmdb:
            status = f"{_status_subject(software, product)} не используется."
        elif not_in_cmdb:
            status = f"{_status_subject(software, product)} не используется."
        elif action == "update":
            status = ("В целях предотвращения возможности эксплуатации данной уязвимости "
                      f"ведутся работы по обновлению {product} до неуязвимой версии.")
    if not status:
        status = ("В целях предотвращения возможности эксплуатации данной уязвимости "
                  f"ведутся работы по обновлению {product} до неуязвимой версии.")
    return [f"{first} {status}"]


def _vuln_block_lines(blk: dict, sender: str = "") -> list[str]:
    """Один абзац про уязвимость (как в эталоне), без перечня мер и CVE."""
    return _vuln_paragraph(blk)

def render_reply(*, plan: dict, templates: dict | None = None, letter_number: str = "",
                 letter_date: str = "", org_name: str = ORG_NAME, addr_count: int = 1,
                 active_vulns: list[dict] | None = None,
                 addresses: list[str] | None = None) -> tuple[str, dict]:
    """Рендер ответа из плана (+ блок уязвимостей для vulnerability-писем)."""
    key = plan.get("template_key") or "hacker"
    skel = (templates or {}).get(key) or {}
    if not skel and key != "other":
        key = "other"
        skel = (templates or {}).get("other") or {}
    header = (skel.get("header") or "Ответ на письмо {{num}} от {{date}}").replace(
        "{{num}}", letter_number or "").replace("{{date}}", _norm_date(letter_date) or "")
    intro = (skel.get("intro") or "Сообщаем о принятых мерах по повышению защищенности инфраструктуры {{org}}.").replace(
        "{{org}}", org_name)
    outro = (skel.get("outro") or "").replace(
        "{{signer}}", skel.get("signer") or "")
    block_tpl = skel.get("block_template") or "{{n}}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {{intro}}, приняты следующие меры защиты:"

    lines = [header, "", intro]
    key_num = (letter_number or "").replace("/", "-")

    if key == "vulnerability":
        plan_vulns = [b for b in (plan.get("blocks") or [])
                      if b.get("threat_type") == "vulnerability"]
        vulns = active_vulns or plan_vulns
        if vulns:
            # NVD-дубли уже обогащённой BDU-записи (тот же CVE) не выводим дважды.
            bdu_cves = {_norm_cve_key(v.get("cve_id"))
                        for v in vulns if v.get("bdu_id")}
            vulns = [v for v in vulns
                     if v.get("bdu_id")
                     or _norm_cve_key(v.get("cve_id")) not in bdu_cves]
        inserts_bdu, inserts_cve = {}, {}
        for item in _load_vuln_inserts().get(key_num, []):
            bdu_key = _norm_bdu_key(item.get("after_bdu"))
            cve_key = _norm_cve_key(item.get("after_cve"))
            if bdu_key:
                inserts_bdu.setdefault(bdu_key, []).extend(item.get("lines") or [])
            if cve_key:
                inserts_cve.setdefault(cve_key, []).extend(item.get("lines") or [])
        if vulns:
            for v in vulns:
                lines.append(_vuln_paragraph(v, key_num)[0])
                lines.extend(inserts_bdu.get(_norm_bdu_key(v.get("bdu_id")), []))
                lines.extend(inserts_cve.get(_norm_cve_key(v.get("cve_id")), []))
        else:
            lines.append("")
            lines.append(NO_RISK_TEXT_C)
        for tail in _load_vuln_tails().get(key_num, []):
            lines.append(tail)
    elif key == "other":
        lines.append("")
        lines.append(skel.get("no_risk_text") or
                     "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации.")
    else:
        numbered = bool(skel.get("number_blocks", key == "hacker"))
        plan_blocks = list(plan.get("blocks") or [])
        intro_overrides = _load_letter_intros().get(key_num, {})
        for i, blk in enumerate(plan_blocks, 1):
            intro_phrase = blk.get("intro") or "реализуемыми угрозами безопасности информации"
            if str(i) in intro_overrides:
                intro_phrase = " ".join(intro_overrides[str(i)].split())
            if blk.get("fixed_header"):
                override = _load_letter_headers().get((letter_number or "").replace("/", "-"))
                head = override or (skel.get("empty_block_text")
                        or "В целях предотвращения реализации угроз, связанных со случаем компрометации "
                           "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                           "приняты следующие меры защиты:")
            elif numbered:
                if "{{n}}" in block_tpl:
                    head = block_tpl.replace("{{n}}", str(i)).replace("{{intro}}", intro_phrase)
                else:
                    head = f"{i}. " + block_tpl.replace("{{intro}}", intro_phrase)
            else:
                head = block_tpl.replace("{{n}}", "").replace("{{n}}. ", "").replace("{{intro}}", intro_phrase).strip()
            if i > 1:
                lines.append("")
            lines.append(head)
            sender = ", ".join(addresses[:8]) if addresses else ""
            for m in blk.get("measures") or []:
                t = m['text'].replace("{{sender}}", sender) if sender else m['text']
                lines.append(f"  {t}")
        if not plan_blocks:
            lines.append("")
            if any(v.get("cmdb_error") for v in (active_vulns or [])):
                lines.append("Проверка применимости уязвимостей не завершена: CMDB недоступна. Требуется ручная проверка.")
            else:
                lines.append(NO_RISK_TEXT_C)

    # Защита от неразрешённых плейсхолдеров (LLM иногда копирует {{...}} из шаблонов)
    lines = [ln for ln in lines if "{{" not in ln]
    text = "\n".join(lines)
    return text, {"template_key": key, "header": header, "intro": intro}


NO_RISK_TEXT_C = "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации."


# --- интеграция для worker/gateway --------------------------------------------

def _reply_result(plan: dict, templates: dict | None, letter_number: str, letter_date: str,
                  org_name: str, addr_count: int, active_vulns: list[dict],
                  addresses: list[str] | None) -> dict:
    """Рендер текста/docx + сборка plan_json. Общая часть generate_reply*."""
    _apply_letter_measure_plan(plan, letter_number, addr_count)
    text, _meta = render_reply(plan=plan, templates=templates, letter_number=letter_number,
                              letter_date=letter_date, org_name=org_name,
                              addr_count=addr_count, active_vulns=active_vulns or [],
                              addresses=addresses)
    plan_blocks = [
        {
            "number": b.get("number"), "threat_id": b.get("threat_id"), "fragment_key": b.get("fragment_key"),
            "intro": b.get("intro"), "threat_type": b.get("threat_type"),
            "description": (b.get("description") or "")[:500],
            "measures": b.get("measures") or [],
        }
        for b in plan.get("blocks") or []
    ]
    plan_json = json.dumps({"template_key": plan.get("template_key"), "llm": plan.get("llm", False),
                            "blocks": plan_blocks}, ensure_ascii=False)
    return {
        "text": text,
        "plan": plan,
        "plan_json": plan_json,
        "docx": render_reply_docx(text),
        "candidates": [m for b in plan.get("blocks") or [] for m in (b.get("new_measures") or [])],
        "llm_used": bool(plan.get("llm")),
    }


def _plan_inputs(db, doc_id: int, letter_type: str | None, blocks: list[dict] | None,
                 active_vulns: list[dict] | None, letter_number: str, letter_date: str):
    """Достраивает letter_type/number/date из документа и готовит блоки плана."""
    from shared.models import Document
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if doc:
        letter_type = letter_type or doc.letter_type
        letter_number = letter_number or doc.letter_number
        letter_date = letter_date or doc.letter_date
    plan_in = blocks or []
    if (letter_type or "hacker").lower() == "vulnerability" and active_vulns:
        plan_in = _vulns_to_blocks(active_vulns)
    return letter_type, letter_number, letter_date, plan_in


def generate_reply(db, doc_id: int, *, letter_type: str | None = None, blocks: list[dict] | None = None,
                   active_vulns: list[dict] | None = None, addr_count: int = 1,
                   letter_number: str = "", letter_date: str = "", org_name: str = ORG_NAME,
                   use_llm: bool | None = None, addresses: list[str] | None = None) -> dict:
    """Полная генерация: план (LLM/fallback) → текст + docx + план-json + кандидаты."""
    letter_type, letter_number, letter_date, plan_in = _plan_inputs(
        db, doc_id, letter_type, blocks, active_vulns, letter_number, letter_date)
    plan = plan_reply(db=db, letter_type=letter_type or "hacker", blocks=plan_in,
                      addr_count=addr_count, use_llm=use_llm, letter_number=letter_number)
    templates = load_reply_resources(db)[2]
    return _reply_result(plan, templates, letter_number, letter_date, org_name,
                         addr_count, active_vulns, addresses)


async def generate_reply_async(db, doc_id: int, *, letter_type: str | None = None,
                               blocks: list[dict] | None = None,
                               active_vulns: list[dict] | None = None, addr_count: int = 1,
                               letter_number: str = "", letter_date: str = "",
                               org_name: str = ORG_NAME, use_llm: bool | None = None,
                               addresses: list[str] | None = None) -> dict:
    """Асинхронный twin generate_reply() для воркеров конвейера.

    Отличие ровно одно: план строится через plan_reply_async, поэтому ожидание
    ответа vLLM не блокирует event loop. БД здесь по-прежнему синхронная
    (SQLAlchemy Session) — она работает в потоке обработчика, а конкурентность
    писем обеспечивается шиной и семафором LLM."""
    letter_type, letter_number, letter_date, plan_in = _plan_inputs(
        db, doc_id, letter_type, blocks, active_vulns, letter_number, letter_date)
    plan = await plan_reply_async(db=db, letter_type=letter_type or "hacker", blocks=plan_in,
                                  addr_count=addr_count, use_llm=use_llm,
                                  letter_number=letter_number)
    templates = load_reply_resources(db)[2]
    return _reply_result(plan, templates, letter_number, letter_date, org_name,
                         addr_count, active_vulns, addresses)


def persist_candidates(db, document_id: int, candidates: list[dict]) -> list[int]:
    from shared.models import MeasureCandidate
    ids = []
    for c in candidates:
        snap = MeasureCandidate(document_id=document_id, threat_id=c.get("threat_id"),
                                text=c["text"], note=c.get("note") or "")
        db.add(snap)
        db.flush()
        ids.append(snap.id)
    return ids


def _obj_attr(obj, name, default=""):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def build_annotated_preview(db, response_plan: dict, threats, addr_count: int = 1) -> list[dict]:
    """Секции предпросмотра с аннотациями мер (source: library|new, candidate_id)."""
    sections = []
    for i, blk in enumerate(response_plan.get("blocks") or [], 1):
        t = threats[i - 1] if i - 1 < len(threats) else None
        measures = [m["text"] for m in blk.get("measures") or []]
        annotations = [{"text": m["text"], "source": m.get("source", "library"),
                        "candidate_id": m.get("candidate_id")} for m in blk.get("measures") or []]
        from shared.generator.reply_preview import _base_measures_for_threat_type, _inflect
        tt = blk.get("threat_type") or ""
        base = _inflect(_base_measures_for_threat_type(db, tt) or [], addr_count)
        measure_options = list(base)
        for m in annotations:
            if m["source"] == "new" and m["text"] not in measure_options:
                measure_options.append(m["text"])
        if blk.get("fixed_header"):
            head = ("В целях предотвращения реализации угроз, связанных со случаем компрометации "
                    "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                    "приняты следующие меры защиты:")
        elif len(response_plan.get("blocks") or []) == 1 and not (t and _obj_attr(t, "id")):
            head = f"В целях предотвращения возможности реализации угроз безопасности информации, связанных с {blk.get('intro') or 'угрозой безопасности информации'}, приняты следующие меры защиты:"
        else:
            head = f"{i}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {blk.get('intro') or 'угрозой безопасности информации'}, приняты следующие меры защиты:"
        sections.append({
            "threat_id": blk.get("threat_id") or _obj_attr(t, "id", 0),
            "number": blk.get("number") or i,
            "prefix": f"{i}. " if len(response_plan.get("blocks") or []) > 1 else "",
            "description": _obj_attr(t, "theme", "") or blk.get("intro") or "",
            "measures": measures,
            "measures_preview": measures,
            "measure_annotations": annotations,
            "measure_options": measure_options,
            "base_measures": base,
            "threat_type": blk.get("threat_type") or "",
            "intro_text": head,
            "section_text": head + "\n" + "\n".join(f"  {m}" for m in measures),
        })
    return sections
