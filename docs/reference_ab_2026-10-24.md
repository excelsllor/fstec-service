# A/B reference-профиля — 2026-10-24

Сравнение reply, собранного без `plan_reply` (reference/fallback), с текущим сохранённым reply
для 22 документов корпуса. Метрика — difflib по словам.

| Показатель | Значение |
|---|---:|
| Документов | 22 |
| Средняя similarity | **0.9969** |
| Минимальная similarity | **0.9609** |
| Документов ниже 0.95 | **0** |

По типам:
- hacker (11 писем): similarity **1.0** — выводы идентичны;
- vulnerability (11 писем): 9 писем 1.0, два письма 0.9609/0.9710 (меняются формулировки,
  состав блоков/мер не падает; reference-хвосты и `_vuln_paragraph` остаются).

Включено только для hacker-писем с reference-профилем (`FSTEC_REPLY_LLM_MODE=reference`);
для vulnerability `plan_reply` оставлен, чтобы не менять формулировки без эталонного A/B.
`plan_reply` ограничен `FSTEC_PLAN_MAX_TOKENS=2500`.

Скрипт: `ab_reference.py` (сервер), raw: `/home/raport/ab_reference.json`.

## Merged analyze+extract

На 9-81/9-89/9-93 число threats/iocs совпало с раздельным прогоном. На 9-85 новый результат
содержит 44 IoC вместо 45: отсутствует 	elegram.org, которого нет в тексте документа
(position=0), то есть старый результат был лишним. Merged включён для не-vulnerability
классификации; vulnerability оставлен на раздельные вызовы.
