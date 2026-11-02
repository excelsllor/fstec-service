# FSTEC микроcервисы (services/)

Архитектура ТЗ 2.1–2.6: gateway (REST) + 4 воркера, событийная шина.

## Локальный запуск (без Kafka/Redis/Postgres; SQLite-шина)

```powershell
cd services
.\run_local.ps1        # PowerShell: gateway + 4 воркера в отдельных процессах
# или: bash run_local.sh (Linux/РЕД ОС)
```

Поднимится:
- `http://127.0.0.1:8666` — API Gateway (OpenAPI: `/api/docs`);
- воркеры ingest → llm → security → reporting (логи: `services/data/logs/*.log`).

Окружение dev: `FSTEC_EVENT_BUS=sqlite` (межпроцессная шина на общей SQLite-БД),
`FSTEC_SECURITY_MODE=mock` (без внешних NVD/BDU), `CMDB_PROVIDER=mock`,
`FSTEC_LLM_PROVIDER=heuristic`, `FSTEC_OCR_ENABLED=false`.
Данные: `services/data/fstec_services.db`.

### Проверка сквозного сценария

```powershell
python tools\services_smoke.py
```

Смоук: создаёт dev-админа (`smoke` / `smoke-pass-123`, только для локальной разработки),
загружает письмо и ждёт `uploaded → parsed → analyzed → assessed → completed`,
проверяет уязвимость (source, cmdb_match, current/target версии), карточку индикаторов
(DOCX) и проект ответа.

## Шина событий

`FSTEC_EVENT_BUS`:
- `memory` — внутри процесса (тесты/CI);
- `sqlite` — локальный мульти-процессный запуск (таблицы `bus_message`/`bus_cursor`,
  курсор на топик: рестарт воркера не переигрывает обработанное);
- `kafka` — prod (`docker-compose.yml` + redis/postgres).

## Тесты

```powershell
cd services
python -m pytest tests -q
```

## Продакшн-инфраструктура

`docker-compose.yml` (kafka + redis + postgres + 5 сервисов), `.env.example`.
Для реального контура: `FSTEC_SECURITY_MODE=live`, `CMDB_PROVIDER=rest`,
`FSTEC_LLM_PROVIDER=vllm`, `FSTEC_OCR_ENABLED=true`.