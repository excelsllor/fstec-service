"""Извлечение мер из эталонных DOCX (готовые ответы ФСТЭК) в формат библиотеки.

Структура эталона (на примере 9-114) — это НЕ «заголовок блока + indented list»,
а абзацы вида:

    Уязвимость <описание> (BDU:2021-00364, уровень опасности ... критический),
    связанная с <причина>. <МЕРА>;
    ...
    Дополнительно приняты следующие компенсирующие меры:
    ограничено использования символа подстановки %J в команде "print" ...;

То есть мера лежит ВНУТРИ абзаца, в последнем предложении, а не отдельной
строкой. Парсер из tools/measures_extract_from_etalons.py на это рассчитан не
был и молча возвращал 0 мер — поэтому здесь свой разбор:

  * режем текст на абзацы;
  * внутри абзаца, начинающегося с «Уязвимость», берём хвост после
    «связанная с …»: это и есть мера по этой уязвимости;
  * «Дополнительно приняты следующие компенсирующие меры:» + следующие абзацы —
    дополнительные меры;
  * классифицируем по формулировке (vulnerability / phishing / compromise);
  * дедупликация по нормализованному тексту.

Запуск:
    python tools/build_measures_from_etalons.py --merge
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from shared.parsers import parse_file  # noqa: E402

NORM_RE = re.compile(r"[^а-яёa-z0-9 ]+")
ADDR_PLACEHOLDER_RE = re.compile(r"\{\{\s*\w+\s*\}\}")

# «Уязвимость <что> (BDU:…), связанная с <причина>.» — начало абзаца-уязвимости.
VULN_PARA_RE = re.compile(r"^\s*Уязвимость\s", re.IGNORECASE)
# Граница, за которой в абзаце начинается собственно мера.
CAUSE_RE = re.compile(r"связанн\w*\s+с\s+.+?\.(\s|$)", re.IGNORECASE | re.DOTALL)
# Хвост абзаца, который нужно отбросить: он несёт BDU/CVSS-оценку, а не меру.
BDU_TAIL_RE = re.compile(r"\(BDU:[^)]*\)", re.IGNORECASE)

EXTRA_HEADER_RE = re.compile(
    r"(Дополнительно\s+приняты\s+следующие\s+компенсирующие\s+меры|"
    r"Дополнительно\s+предприняты\s+меры|"
    r"компенсирующие\s+меры)", re.IGNORECASE)
INTRO_RE = re.compile(
    r"(?:Выявлены|Обнаружены)\s+(?:признаки\s+)?(.+?),\s*"
    r"(?:относится|относятся|относиться)\s+к\s+угрозам", re.IGNORECASE | re.DOTALL)

VULN_RE = re.compile(
    r"(обновлен|обновля|установ|внедр|применен|применён|верси|патч|уязвимост|устран|"
    r"исключен|отключ|не примен|не подвержен|не повержен|не использу|не эксплуатир|"
    r"ограничен|закрыт|проводятся работы|проводится|ведутся работы|предотвращ|"
    r"неуязвим|компенсирующ)",
    re.IGNORECASE)
PHISHING_RE = re.compile(
    r"(фишинг|вложени|почтов|отправител|sandbox|песочниц|антивирус|"
    r"электронн\w* почт|url-адрес)", re.IGNORECASE)
COMPROMISE_RE = re.compile(
    r"(журнал|мониторинг|скан|аудит|учетн\w* запис|контрол|сегмент|"
    r"межсетев|правил\w* систем)", re.IGNORECASE)

# Одинаковая обвязка вокруг меры по уязвимости — не часть сути меры.
VULN_WRAP_RE = re.compile(
    r"^в\s+целях\s+предотвращения\s+возможности\s+эксплуатации\s+данной\s+"
    r"уязвимости\s+", re.IGNORECASE)

# 73% vulnerability-мер эталонов — это один и тот же хвост с разным продуктом.
# Храним их шаблоном: библиотека уезжает в prompt плана целиком (provider.py:_plan_payload),
# и 124 копии под каждый продукт раздували prefill до ~7k токенов.
# Порядок важен: сначала более специфичные хвосты, потом общие.
T_UPD = "В целях предотвращения возможности эксплуатации данной уязвимости ведутся работы по обновлению {{software}} до неуязвимой версии"
T_REG = "Производится регулярное обновление {{software}} с предварительным тестированием обновлений"
VULN_TEMPLATES: list[tuple[re.Pattern, str]] = [
    # По словоформам: «не применяется» / «не применяются» в эталонах чередуются.
    (re.compile(r"\bне применя\w*\b", re.IGNORECASE), "{{software}} не применяется"),
    (re.compile(r"\bне использу\w*\b", re.IGNORECASE), "{{software}} не используется"),
    (re.compile(r"\bне эксплуатируется\b", re.IGNORECASE), "{{software}} не эксплуатируется"),
    # «не повержена» — опечатка в эталоне 9-157, терпим к ней.
    (re.compile(r"\bне (?:подвержен|повержен)\w*\b", re.IGNORECASE),
     "Используемая версия {{software}} не подвержена данной уязвимости"),
    (re.compile(r"установк\w* (?:накопительных )?обновлен\w* безопасности .+"
                r"|накопительных обновлений безопасности .+", re.IGNORECASE),
     "Установлены обновления {{software}}"),
    (re.compile(r"ведутся работы по обновлению .+? до неуязвимой версии", re.IGNORECASE), T_UPD),
    (re.compile(r"регулярно проводятся (?:работы по обновлению|обновления) .+"
                r"|регулярно проводится обновление .+"
                r"|регулярно производится обновление .+", re.IGNORECASE), T_REG),
    (re.compile(r"ведутся работы по обновлению .+", re.IGNORECASE), T_UPD),
    (re.compile(r"ограничено использовани\w* .+", re.IGNORECASE), "Ограничено использование {{software}}"),
]


def templatize(text: str) -> str | None:
    """Шаблон vulnerability-меры, если она шаблонная; иначе None (оставляем как есть)."""
    s = VULN_WRAP_RE.sub("", text).strip()
    if not s:
        return None
    for pat, canon in VULN_TEMPLATES:
        if pat.search(s):
            return canon
    return None


def norm(text: str) -> str:
    return " ".join(NORM_RE.sub(" ", text.lower()).split())


def strip_tail(text: str) -> str:
    return " ".join(text.strip().rstrip(";. ").split())


def classify(text: str) -> tuple[str, str]:
    if VULN_RE.search(text):
        return "vulnerability", "vulnerability,patch"
    if PHISHING_RE.search(text):
        return "phishing", "phishing"
    if COMPROMISE_RE.search(text):
        return "compromise", "compromise"
    return "hacker", "hacker,base"


MEASURE_NOISE_RE = re.compile(
    r"^(дополнительно\s+)?(приняты|предприняты|сообщаем)?\s*следующие\s+"
    r"(компенсирующие\s+)?меры\b", re.IGNORECASE)


def split_multi(text: str) -> list[str]:
    """«Ведётся переход на X. Дополнительно Y не используются» -> две меры.

    В эталонах встречаются меры в двух предложениях; в письме это читается
    как одна неразбитая мера, поэтому режем по '. Дополнительно'. Хвост вида
    «Дополнительно приняты следующие меры:» — это заголовок, а не мера, его
    выбрасываем.
    """
    if not re.search(r"\.\s*Дополнительно\s+(?:сообщаем|приняты|приняли)", text, re.IGNORECASE):
        return [text]
    head, tail = re.split(r"\.\s*(?=Дополнительно\s+(?:сообщаем|приняты|приняли))",
                          text, maxsplit=1, flags=re.IGNORECASE)
    parts = [strip_tail(p) for p in (head, tail) if p.strip()]
    parts = [p for p in parts if len(p) >= 25 and not MEASURE_NOISE_RE.match(p)]
    return parts if len(parts) > 1 else [text]



def _split_tail_tail(text: str) -> str:
    """Абзац «Уязвимость … (BDU:…). <мера>» -> «<мера>»."""
    s = BDU_TAIL_RE.sub(" ", text)
    m = CAUSE_RE.search(s)
    if m:
        return s[m.end():]
    # Причины нет — берём текст после первой точки, где кончается описание.
    dot = s.find(". ")
    return s[dot + 2:] if dot >= 0 else ""


def extract_measures(text: str) -> tuple[list[str], list[str]]:
    """(меры, intro-фрагменты) из текста одного эталона."""
    measures: list[str] = []
    intros: list[str] = []
    in_extra = False

    for raw in text.splitlines():
        line = " ".join(raw.split())
        if not line:
            continue
        if INTRO_RE.search(line):
            m = INTRO_RE.search(line)
            frag = " ".join(m.group(1).split())
            if frag and frag not in intros:
                intros.append(frag)
            continue
        if EXTRA_HEADER_RE.search(line):
            in_extra = True
            continue
        if VULN_PARA_RE.match(line):
            in_extra = False
            tail = strip_tail(_split_tail_tail(line))
            if len(tail) > 20:
                measures.append(tail)
            continue
        if in_extra:
            tail = strip_tail(BDU_TAIL_RE.sub(" ", line))
            if len(tail) > 20:
                measures.append(tail)
    return measures, intros


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--etalon-dir", default=str(ROOT.parent.parent),
                    help="каталог с эталонными DOCX")
    ap.add_argument("--out", default=str(ROOT / "data" / "generator" / "measures_library.json"))
    ap.add_argument("--merge", action="store_true",
                    help="дописать к существующей библиотеке, не заменяя её")
    ap.add_argument("--no-templates", action="store_true",
                    help="не сворачивать vulnerability-меры в шаблоны {{software}}")
    args = ap.parse_args()

    docs = sorted(Path(args.etalon_dir).glob("*.docx"))
    if not docs:
        print(f"Эталоны не найдены в {args.etalon_dir}", file=sys.stderr)
        return 1

    collected: list[dict] = []
    seen: set[str] = set()
    total_in_docs = 0
    n_templated = 0

    for doc in docs:
        try:
            text = parse_file(str(doc)).text
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {doc.name}: не разобран ({exc})", file=sys.stderr)
            continue
        measures, _ = extract_measures(text)
        total_in_docs += len(measures)
        added = 0
        for raw_m in measures:
            # Тип определяем по исходному тексту: после шаблонизации признаки
            # («обновля…») уже не видны, и мера уезжала бы в hacker вместо vulnerability.
            threat_type, tags = classify(raw_m)
            for m in split_multi(raw_m):
                if not args.no_templates and threat_type == "vulnerability":
                    tpl = templatize(m)
                    if tpl:
                        m = tpl
                        n_templated += 1
                key = norm(m)
                if key in seen:
                    continue
                seen.add(key)
                collected.append({
                    "text": m,
                    "threat_type": threat_type,
                    "tags": tags,
                    "addr_inflection": bool(ADDR_PLACEHOLDER_RE.search(m)),
                    "source": "etalon",
                })
                added += 1
        if measures:
            print(f"{doc.name}: мер {len(measures)}, новых {added}")

    print(f"\nвсего мер в эталонах: {total_in_docs}, уникальных: {len(collected)}")
    if not args.no_templates:
        print(f"свёрнуто в шаблоны {{software}}: {n_templated}")

    if args.merge:
        out_path = Path(args.out)
        existing = json.load(open(out_path, encoding="utf-8")) if out_path.exists() else []
        added_existing = 0
        for m in existing:
            key = norm(m["text"])
            if key in seen:
                continue
            seen.add(key)
            collected.append(m)
            added_existing += 1
        print(f"слияние с {out_path.name}: было {len(existing)}, добавлено обратно {added_existing}")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    json.dump(collected, open(out_path, "w", encoding="utf-8"),
              ensure_ascii=False, indent=1)

    by_type: dict[str, int] = {}
    for m in collected:
        by_type[m["threat_type"]] = by_type.get(m["threat_type"], 0) + 1
    print(f"\nзаписано {len(collected)} мер -> {out_path}")
    for t, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
        print(f"  {t:14} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
