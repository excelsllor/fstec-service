# Финальные быстрые замеры — 2026-10-25

Конфигурация: SHA dedupe, reference для hacker, merged analyze+extract, **параллельные chunks**,
BERT+regex + parent-domain, LLM-IoC для vulnerability, `plan_reply max_tokens=2500`,
**guided JSON выключен**, с guided-fallback на повторной попытке.

| Сценарий | p50 | p95 | max | Throughput | Ошибки |
|---|---:|---:|---:|---:|---:|
| 3 hacker, 3 параллельно | **24.2 с** | 24.2 с | 56.7 с | 189.4 док/ч | 0 |
| 8 hacker, 8 параллельно | **83.2 с** | 117.8 с | 134.0 с | **214.3 док/ч** | 0 |
| 8 hacker + chunked prefill | 83.2 с | 121.8 с | 138.1 с | 208.1 док/ч | 0 |

Vulnerability: 9-152 — 96 с, 9-148 — 117 с.

Контроль качества guided off vs guided on на 8 письмах: **наборы IoC и число threats
полностью совпали** (`+0/-0` по каждому письму). Guided-fallback включён на случай
невалидного JSON.

Chunked prefill **отключён**: на T4 он дал p50 83.2 с против 62.7 с без него.
CUDA graphs включены (vLLM `enforce_eager=False`, `max_seq_len_to_capture=12288`).

Сырые данные: `speed_quick_final_2026-10-25.json`,
`speed_quick_unguided_2026-10-25.json`,
`speed_quick_chunked_prefill_2026-10-25.json`.
