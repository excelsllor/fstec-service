# Руководство администратора

## 1. Состав системы

Микросервисы: `api-gateway`, `ingest-service`, `llm-service`, `security-service`,
`reporting-service`, `nginx`; инфраструктура: Kafka, PostgreSQL, Redis, vLLM.
Данные — named volume `data` (`/app/data`), БД — PostgreSQL.

## 2. Установка

```bash
cd fstec-service/services
cp .env.example .env
# заполнить POSTGRES_PASSWORD, REDIS_PASSWORD, FSTEC_SECRET_KEY, GLPI_*, VLLM_*
docker compose -f docker-compose.yml -f docker-compose.t4.yml up -d --build
```

Проверка: `docker ps` — все контейнеры `healthy`; `curl http://localhost/api/auth/status`.

## 3. Ключевые настройки

- `FSTEC_LLM_PROVIDER=vllm`, `VLLM_BASE_URL`, `VLLM_MODEL`.
- `FSTEC_LLM_WARMUP_ENABLED=1`, `FSTEC_LLM_WARMUP_INTERVAL_S=300` — прогрев/keepalive vLLM.
- `FSTEC_OCR_ENABLED=true`, `FSTEC_OCR_ENGINE=tesseract`, `FSTEC_OCR_DEVICE=cpu`.
- `CMDB_PROVIDER=glpi`, `GLPI_URL`, `GLPI_API=v2`, `GLPI_AUTH=oauth`, `GLPI_CLIENT_ID/SECRET`,
  `GLPI_USERNAME/PASSWORD`.
- `FSTEC_DISABLE_DOCS=1` в prod; статическая спецификация — `docs/openapi.json`.
- `FSTEC_OCR_ENABLED=false` отключает OCR только при отсутствии Tesseract.

## 4. Первый запуск

На экране входа появится bootstrap-пароль администратора (показывается один раз).
После входа создайте пользователей в «Пользователи» и смените пароль.

## 5. Эксплуатация

- Логи: `docker logs -f fstec-llm`, `fstec-security`, `fstec-reporting`, `fstec-ingest`.
- vLLM: `docker logs fstec-vllm`; healthcheck `/health`.
- Диагностика UI: раздел «Диагностика» (Kafka, сервисы, БД, LLM).
- Перезапуск: `docker compose ... restart <service>`.
- Обновление: сначала backup, затем `build` и `up -d`.

## 6. Резервное копирование

```bash
# PostgreSQL
docker exec fstec-postgres pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB" | gzip > backup_$(date +%F).sql.gz
# Файлы (uploads/reports/data)
docker run --rm -v services_data:/data -v "$PWD":/backup alpine \
  tar czf /backup/data_$(date +%F).tgz -C / data
```
Хранить копии вне хоста; проверять восстановление на тестовой БД.

Готовый скрипт: services/tools/backup.sh (OUT_DIR, PG_CONTAINER, DATA_VOLUME).
Для зависших документов: python tools/watchdog.py --older-than 30 (просмотр)
или --mark-failed (перевод в failed с записью причины).

## 7. Безопасность

- `.env` — `chmod 600`, не коммитить.
- TLS 1.3 и Kafka TLS/SASL — обязательны для prod (сейчас не настроены).
- Ограничить доступ к vLLM/БД/Redis сетевыми правилами.
- Обновлять базовые образы и зависимости (см. `security_vulnerability_report.md`).
- Аудит: `audit_log`; часть операций просмотра/скачивания пока не покрыта.

## 8. Ограничения текущей версии

- Нет HA/RTO-автоматики, автобэкапов и ручного режима с уведомлением оператора.
- Пропускная способность на T4 ≈75 док/ч, KPI 500+/ч требует более мощного GPU/шардирования.
- PaddleOCR не работает (ABI numpy); используется Tesseract CPU.
