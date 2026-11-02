"""Проект ответа в виде структуры секций (для файла редактирования во фронтенде).

Возвращает структуру, аналогичную legacy /api/letters/{id}/response/preview:
  title, intro, sections[] (prefix, description, measures, measures_preview,
  threat_type, measure_options, base_measures, intro_text, section_text).

Строится на новых моделях (Document/Threat/Vulnerability/IoC + справочники
MeasureTemplate / VulnActionTemplate) и переиспользует логику ответа
из response_generator (ТЗ 2.5.2).
"""
import json
import re

from shared.config import ORG_NAME
from shared.generator.response_generator import NO_RISK_TEXT, _inflect


def _library_measures(db, tag: str) -> list[str]:
    """Меры единой библиотеки (measures) по тегу в каноническом порядке."""
    try:
        from shared.generator.templated_reply import _measures_for_tag, load_reply_resources
        library, _, _ = load_reply_resources(db)
        return _measures_for_tag(library, tag)
    except Exception:
        return []


def _normalize_date(dt: str) -> str:
    if not dt:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        return f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    return dt


def _base_measures_for_threat_type(db, threat_type: str) -> list[str]:
    """Меры по умолчанию для типа угрозы из единой библиотеки (measures по тегу)."""
    measures = _library_measures(db, threat_type)
    if not measures:
        measures = _library_measures(db, "phishing")
    return measures


def build_preview(*, db, document, threats, vulnerabilities, iocs) -> dict:
    """Секции ответа для редактора (ответ на ТЗ 2.5.2)."""
    from shared.models import GeneratedResponse
    resp = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == document.id)
            .order_by(GeneratedResponse.id.desc()).first())
    if resp and resp.plan_json:
        from shared.generator.templated_reply import build_annotated_preview
        plan = json.loads(resp.plan_json)
        title = (f"Ответ на письмо {document.letter_number} от {_normalize_date(document.letter_date)}"
                 if document.letter_number else "Ответ на письмо")
        intro = f"Сообщаем о принятых мерах по повышению защищенности инфраструктуры {ORG_NAME}."
        sections = build_annotated_preview(db, plan, threats, addr_count=len(iocs))
        return {
            "title": title, "intro": intro, "sections": sections,
            "text": resp.content or "", "llm": bool(plan.get("llm")),
        }

    num = document.letter_number or ""
    dt = _normalize_date(document.letter_date or "")
    title = f"Ответ на письмо {num} от {dt}".strip() if num else "Ответ на письмо"
    intro = "Сообщаем о принятых мерах по повышению защищенности информационной инфраструктуры."

    addr_count = len({i.value.split(":")[0] for i in iocs if i.ioc_type in ("ip", "domain")})

    # Приоритет: уязвимости (тип vulnerability) иначе угрозы
    active_vulns = [v for v in vulnerabilities if v.cmdb_match or v.is_applicable is True]

    lines = [title, "", intro]

    if active_vulns:
        lines.append("")
        lines.append("Выявлены уязвимости, затрагивающие используемое программное обеспечение. "
                     "Требуется срочно выполнить обновление:")
        sections = []
        for v in vulnerabilities:
            if (v.action_type or "").lower() == "exclude":
                continue
            sw = v.software or "программного обеспечения"
            cur = ""
            tgt = v.target_version or v.fixed_version
            rec = ""
            if rec:
                text = f"{rec};"
            elif cur and tgt:
                text = f"обновить {sw} до {tgt};"
            else:
                text = f"обновить {sw};"
            lines.append(f"  - {text}")
            sections.append({
                "threat_id": 0,
                "number": 0,
                "prefix": "",
                "description": f"{v.cve_id or v.bdu_id or sw}",
                "measures": [text],
                "measures_preview": [text],
                "threat_type": "vulnerability",
                "measure_options": _library_measures(db, "phishing"),
                "base_measures": [],
                "intro_text": "",
                "section_text": text,
            })
        sections = sections if sections else _fallback_sections(threats, addr_count, db)
    elif threats:
        sections = []
        multiple = len(threats) > 1
        for t in threats:
            prefix = f"{t.number}. " if multiple else ""
            desc = re.sub(r"\s+", " ", (t.theme or t.description or "")).strip() or "угрозой безопасности информации"
            measures = _base_measures_for_threat_type(db, t.threat_type)
            measures = _inflect(measures, addr_count)
            if t.measures and t.measures.strip():
                saved = [m.strip() for m in t.measures.split("\n") if m.strip()]
                if saved:
                    measures = saved
            intro_text = (f"{prefix}В целях предотвращения возможности реализации угроз безопасности "
                          f"информации, связанных с {desc}, приняты следующие меры защиты:")
            base = _inflect(_base_measures_for_threat_type(db, t.threat_type)
                            or _library_measures(db, "phishing"), addr_count)
            measure_options = list(base)
            if t.threat_type == "compromise":
                measure_options = _inflect(_library_measures(db, "compromise"), addr_count)
            section_text = intro_text + "\n" + "\n".join(f"  {m}" for m in measures)
            sections.append({
                "threat_id": t.id,
                "number": t.number,
                "prefix": prefix,
                "description": desc,
                "measures": measures,
                "measures_preview": measures,
                "threat_type": t.threat_type or "",
                "measure_options": measure_options,
                "base_measures": base,
                "intro_text": intro_text,
                "section_text": section_text,
            })
            lines.extend([intro_text] + [f"  {m}" for m in measures])
    else:
        sections = []
        lines.append("")
        unknown = [v for v in vulnerabilities if v.cmdb_error and not v.cmdb_match]
        if unknown:
            lines.append("Проверка применимости уязвимостей не завершена: CMDB недоступна. Требуется ручная проверка.")
        else:
            lines.append(NO_RISK_TEXT)

    return {
        "title": title,
        "intro": intro,
        "sections": sections,
        "text": "\n".join(lines),
    }


def _fallback_sections(threats, addr_count, db):
    sections = []
    for t in threats:
        measures = _inflect(_library_measures(db, "phishing"), addr_count)
        intro_text = (f"В целях предотвращения возможности реализации угроз безопасности информации, "
                      f"связанных с {t.theme or 'угрозой безопасности информации'}, приняты следующие меры защиты:")
        sections.append({
            "threat_id": t.id, "number": t.number, "prefix": "",
            "description": t.theme or "", "measures": measures,
            "measures_preview": measures, "threat_type": t.threat_type or "",
            "measure_options": measures, "base_measures": measures,
            "intro_text": intro_text, "section_text": intro_text,
        })
    return sections
