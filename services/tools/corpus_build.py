#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Сборка корпуса для оценки качества (Step 2).

Для каждого кейса из CUSTOM_CORPUS_DIR собирает:
  - real.pdf     -> текст (main) + класс \xe2\x80\x94 из правила, переопределяемое CLASS_OVERRIDES
  - приложения   -> "Сетевые индикаторы компрометации" (ip) и "ограничение обращений к адресам" (dom)
  - парсит golden-индикаторы из приложений (ip/dom, с дедупликацией)
  - текст ответа /:\u0421еть\u0421пас\u0421е\u0421б\u0421ряивая \u0421гу\u0421в\u0421д\u0421fl.. \u043d\u0435 \u0443\u043f\u043e\u043c\u0438\u043d\u0430\u0435\u0442\u0441\u044f \u0432 \u0437\u0430\u0434\u0430\u0447\u0435.

Класс кейcа: в CLASS_OVERRIDES (ручная разметка по эталонным ответам);
иначе регулярка (по тексту PDF).
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# --- ручная разметка классов (обязательна: правило < heuristic по "ка обрабатывать письма") ---
CLASS_OVERRIDES = {
    "9-70": "hacker", "9-77": "compromise", "9-78": "hacker", "9-81": "hacker",
    "9-85": "hacker", "9-89": "hacker", "9-93": "hacker", "9-99": "hacker",
    "9-104": "hacker", "9-107": "hacker", "9-113": "hacker", "9-118": "hacker",
}

IND_RE = re.compile(
    r"(?:IP\s|-?\d{1,11}|Сетевые индикаторы компрометации)\s*", re.IGNORECASE)
IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?!/\d)(?!\d)", re.M)
DOM_RE = re.compile(r"\b(?:[0-9a-zA-Z-]+\.){1,}[a-z]{2,10}\b")

# Линия-индикатор: чистый IP/домен (с опциональным :порт), без пробелов/кириллицы
_INDICATOR_LINE = re.compile(
    r"^\s*(?:hxxps?[:.\[\]\-]?//)?"
    r"(?:[a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]|[a-zA-Z0-9])"
    r"(?:\s*[:.]\[[:.]//?\]\s*)?[a-zA-Z0-9/:.,\[\]\-]*$")


def deobfuscate(text: str) -> str:
    text = text.replace("[.]", ".").replace("(.)", ".")
    text = re.sub(r"^hxxps?\[[:]\]//", "https://", text)
    text = re.sub(r"^hxxps?(\.)//", "https://", text)
    text = re.sub(r"^hxxps?://", "https://", text)
    text = re.sub(r"\[[:]\]//", "://", text)
    return text


def _parse_blocklist(text: str, kind: str) -> list[str]:
    """Детерминированный сбор индикаторов из сплошного списка «адресов на блокировку»:
    линии без пробелов/кириллицы (IP или домен, допускается :порт и [.]-обфускация),
    канонизируются общим экстрактором."""
    from shared.extractor.ioc_extractor import extract_iocs
    out: list[str] = []
    for raw in text.splitlines():
        line = deobfuscate(raw.strip()).strip().rstrip(".;,")
        if not line or " " in line or re.search(r"[а-яёА-ЯЁ]", line):
            continue
        if len(line) > 120:
            continue
        if kind == "ip":
            hit = IP_RE.search(line)
            if hit and hit.group(1) not in out:
                out.append(hit.group(1))
        else:
            hit = DOM_RE.search(line)
            if not hit or line.startswith("ip-"):
                continue
            # каноническая форма через продакшен-экстрактор (обфускация, :port, мусор)
            iocs = extract_iocs(line)
            for d in iocs.domains:
                if d not in out:
                    out.append(d)
    # рекурсивная канонизация на случай табличного склеивания строк списка
    if text.count("\n") >= 3:
        joined = deobfuscate(text).rstrip(".;,")
        if " " not in joined and not re.search(r"[а-яёА-ЯЁ]", joined):
            iocs = extract_iocs(joined)
            for d in iocs.domains:
                if d not in out:
                    out.append(d)
            for ip in iocs.ips:
                ip = ip.split(":")[0]
                if ip not in out:
                    out.append(ip)
    return out


def parse_attachment(text: str, what: str) -> list[str]:
    """Парсит индикаторы из текста приложения (устаревший путь для совместимости)."""
    if not text:
        return []
    if what in ("dom", "ip"):
        return _parse_blocklist(text, what)
    out = []
    for ln in text.splitlines():
        ln = ln.strip().rstrip(";,")
        if not ln:
            continue
        if what == "ip":
            m = IP_RE.search(ln)
            if m and m.group(1) not in out:
                out.append(m.group(1))
        elif what == "dom":
            m = DOM_RE.search(ln)
            if m and len(ln) > 1 and not re.search(r"\d{1,3}:\d", ln.split(" ")[0].lower()):
                d = m.group(0).lower()
                if d not in out and not d.startswith("ip-"):
                    out.append(d)
    return out


def classify(text: str) -> str:
    low = text.lower()
    if re.search(r"хакерск[а-яё]+\s+группировк|фишингов[а-яё]*\s+рассылк", low):
        return "hacker"
    if re.search(r"компрометаци[а-яё]*\s+(?:веб-сайта|программн|ПО|сервера|инфраструктуры)", low):
        return "compromise"
    if re.search(r"(?:bdу|бдu)[:\s]|cve-\d{4}-|уязвимост[а-яё]+", low):
        return "vulnerability"
    return "other"


def extract_meta(text: str) -> dict:
    m = re.search(r"№\s*(\d+[-/]\d+)", text.replace("_", ""))
    number = m.group(1) if m else ""
    date = ""
    pats = [
        r"(\d{1,2})\s+(января|февраля|марта|апреля|мая|июня|июля|августа|сентября|октября|ноября|декабря)\s+(\d{4})",
        r"(\d{1,2})\.(\d{1,2})\.(\d{4})",
        r"(\d{4})-(\d{1,2})-(\d{1,2})",
    ]
    MON = {"января":"01","февраля":"02","марта":"03","апреля":"04","мая":"05","июня":"06",
           "июля":"07","августа":"08","сентября":"09","октября":"10","ноября":"11","декабря":"12"}
    for p in pats:
        m = re.search(p, re.sub(r"[_\s]+", " ", text[:2000]), re.I)
        if m:
            if m.lastindex == 3 and p.startswith(r"(\d{1,2})\.*"):
                day, month, year = m.group(1).zfill(2), m.group(2).zfill(2), m.group(3)
            elif m.lastindex >= 3 and p[0] == r"(":
                date = ""
                continue
            else:
                day, month, year = m.group(1).zfill(2), MON.get(m.group(2).lower(), "01"), m.group(3)
            if 2020 <= int(year) <= 2035:
                date = f"{year}-{month}-{day}"
            break
    return {"number": number, "date": date}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", default=str(ROOT / "corpus" / "real"))
    ap.add_argument("--attachments", default="",
                    help="Каталог с оригинальными приложениями (папки 'К письму X').")
    ap.add_argument("--out", default=str(ROOT / "data" / "quality" / "corpus_index.json"))
    args = ap.parse_args()

    from shared.parsers import parse_file

    corpus_dir = Path(args.corpus)
    cases = {}
    for pdf in sorted(corpus_dir.glob("*.pdf")):
        name = pdf.stem
        result = parse_file(pdf)
        text = (result.text or "").strip()
        main = text
        cls = classify(main)
        case = {
            "id": name, "path": str(pdf), "main": main,
            "full": main,
            "gold": {"classification": CLASS_OVERRIDES.get(name, cls)},
        }
        case["gold"].update(extract_meta(main))
        case["gold"]["ips"] = []
        case["gold"]["domains"] = []

        # «полный» список индикаторов: приложения + списки адресов из тела письма
        body_block_ip: list[str] = []
        body_block_dom: list[str] = []
        left = main
        for marker in ("по «черным» или «белым» спискам:", "ограничение обращений к адресам",
                       "материалами письма осуществляется рассылка", "указанным адресам"):
            while True:
                i = left.lower().find(marker)
                if i < 0:
                    break
                section = left[i: i + 4000]
                tail = section[len(marker):]
                # обрываем секцию на следующем абзаце с кириллическим текстом
                cut = 4000
                for m in re.finditer(r"\n\s*\n", section):
                    frag = section[m.end(): m.end() + 60]
                    if re.search(r"[а-яёА-ЯЁ]", frag):
                        cut = m.start()
                        break
                block = section[len(marker): cut]
                body_block_ip += [x for x in _parse_blocklist(block, "ip") if x not in body_block_ip]
                body_block_dom += [x for x in _parse_blocklist(block, "dom") if x not in body_block_dom]
                left = left[i + 1:]

        # приложения из исходной папки корпуса (если доступны)
        if args.attachments:
            k = Path(args.attachments) / name / f"К письму {name}"
            if k.is_dir():
                for att in sorted(k.glob("*")):
                    if att.name.startswith("~$"):
                        continue
                    if str(att).lower().endswith(".odt"):
                        try:
                            atext = (parse_file(att).text or "")
                        except Exception:
                            atext = ""
                        case["full"] = case["full"] + "\n\n" + atext
                        if "адресам" in atext or "индикаторы" in atext:
                            if "ip-" in att.name or "индикаторы" in atext:
                                case["gold"]["ips"] = _parse_blocklist(atext, "ip") or None
                            elif "адресам" in atext:
                                case["gold"]["domains"] = _parse_blocklist(atext, "dom") or None

        # золото «как должен видеть систему аналитик»: приложения + списки из тела
        att_ips = set(case["gold"].get("ips") or [])
        att_doms = set(case["gold"].get("domains") or [])
        case["gold_full"] = {
            "ips": sorted(att_ips | set(body_block_ip)),
            "domains": sorted(att_doms | set(body_block_dom)),
        }

        cases[name] = case

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(cases, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"Built {len(cases)} cases -> {out}")
    for n, c in cases.items():
        print(f"  {n}: class={c['gold']['classification']} ips={len(c['gold'].get('ips') or [])} "
              f"doms={len(c['gold'].get('domains') or [])} main_chars={len(c['main'])}")


if __name__ == "__main__":
    main()