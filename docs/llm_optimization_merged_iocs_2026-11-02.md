# LLM optimization #3 — merged vulnerability + merged IoC

## Что проверяли

Включили вместе с уже работающим merged-анализом vulnerability-писем:

```text
FSTEC_LLM_MERGED_VULN=1
FSTEC_LLM_MERGED_IOCS=1
```

Цель: merged-вызов должен сразу возвращать IoC и больше не требовать отдельного
fallback-вызова `extract_iocs_llm`.

## Результат на 22 уникальных письмах

- До (только merged vulnerability): **4 мин 07 с**.
- С merged vulnerability + merged IoC: **10 мин 31 с**.
- Завершено: **22/22**, без failed.
- Полевые метрики не изменились:
  - CVSS 99.55%
  - severity 97.29%
  - применимость 99.49%
  - меры F1 98.21%

## Вывод

Совмещённый вариант **существенно медленнее** и качества не добавляет.
`FSTEC_LLM_MERGED_IOCS` откатили в `0`.

Оставлено только успешное изменение:

```text
FSTEC_LLM_MERGED_VULN=1
```

Причина: добавление IoC в merged-схему увеличивает объём генерации vLLM; fallback
IoC-вызов оказывается дешевле, чем расширенный merged-ответ.
