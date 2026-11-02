# Отчёт по аудиту безопасности — FSTEC Service

- **Дата:** 2026-09-21
- **Область:** сервис обработки писем ФСТЭК (микросервисы `services/`, UI `frontend/`, контейнеризация, интеграции BDU/NVD/CMDB, LLM-контур).
- **Тип:** разовый аудит перед выводом на сервер. **Только аудит и отчёт, код не изменялся.**
- **Целевой уровень:** OWASP ASVS 4.0.3, уровень 2.
- **Исполнитель:** внутренний аудит (white-box + grey-box DAST).
- **Версия кода:** рабочее дерево с незакоммиченными правками под prod-деплой (docker-compose, Dockerfile, frontend/nginx).

---

## 1. Резюме

Проведён статический (SAST), зависимостный (SCA), контейнерный и динамический (DAST) анализ, а также аудит конфигурации инфраструктуры и ручная проверка контроля доступа на локально поднятом контуре (Postgres 16 + Redis 7 + Kafka 3.7 + api-gateway + nginx; LLM/OCR-воркеры не поднимались — на стенде нет GPU).

**Главные выводы:**

1. **Критично:** JWT подписывается секретом по умолчанию `dev-insecure-change-me`. Токен, подделанный с этим публично известным секретом, аутентифицируется как `admin` (подтверждено: `HTTP 200`). При незаданном `FSTEC_SECRET_KEY` — полный захват аккаунта администратора.
2. **Высоко:** отсутствует авторизация на уровне объектов (IDOR). Любой аутентифицированный пользователь читает и **изменяет** письма/документы всех остальных (подтверждено чтением и записью чужого документа пользователем с ролью `user`).
3. **Высоко:** bootstrap-пароль администратора выводится в лог открытым текстом (дважды), а строка `bootstrap_secrets` никогда не удаляется — `needs_setup` навсегда остаётся `true`.
4. **Высоко:** дефолтные/пустые креды инфраструктуры: Postgres `fstec/fstec`, Redis без пароля, Kafka `PLAINTEXT` без аутентификации и ACL.
5. **Высоко (деплой-блокер):** `docker-compose.yml` не разворачивается — образ `bitnami/kafka:3.7` отсутствует в реестре (`not found`).
6. **Средне:** wildcard CORS `*`; отсутствие security-заголовков; неработающий за прокси rate-limit и неверный IP в аудите; zip-bomb в парсерах; невалидируемая пагинация (500 + без верхней границы `limit`); уязвимые зависимости (Pillow, ecdsa, react-router); контейнеры от root; непинованный `vllm:latest`; prompt injection в LLM; рассогласование env CMDB.

Сводка по количеству находок: **Critical — 1, High — 5, Medium — 9, Low — 5, Info — 3.**

---

## 2. Методика и окружение

### 2.1. Инструменты

| Класс | Инструмент | Версия/образ | Результат |
|---|---|---|---|
| SAST (Python) | Semgrep | latest | 7 находок |
| SAST (Python) | Bandit | latest | см. `bandit.json` |
| SAST (Python, security-rules) | Ruff `--select S` | latest | 419 (400 — `S101 assert` в тестах) |
| SCA (Python) | pip-audit | latest | 27 уязвимостей в 2 пакетах |
| SCA (JS) | npm audit | bundled | prod: 2 high; +dev: 4 |
| Секреты | Gitleaks (Docker) | `zricethezav/gitleaks` | утечек нет (`[]`), 19 коммитов |
| Контейнеры/FS/конфиги | Trivy (Docker) | `aquasec/trivy` v0.74 | gateway: 1C/94H/112M; nginx: 2C/37H/58M; fs: 11H/4M + 4 misconfig |
| DAST (пассивный/активный) | OWASP ZAP baseline + API scan | `ghcr.io/zaproxy/zaproxy` | baseline 0 FAIL/10 WARN; api 0 FAIL/2 WARN |
| DAST (fuzzing по OpenAPI) | Schemathesis | 4.27.5 | 53 уникальных сбоя |
| Ручные проверки | curl/psql/redis-cli/docker | — | см. раздел 4 |

### 2.2. Тестовый контур

- Docker Desktop 29.7.2 (Windows), **без GPU**.
- Поднято: `postgres:16-alpine`, `redis:7-alpine`, Kafka (заменён на `bitnamilegacy/kafka:3.7`, т.к. штатный образ недоступен), `api-gateway` (образ из `services/Dockerfile`), `nginx` (образ из `frontend/Dockerfile`).
- vLLM (`vllm/vllm-openai`) и PaddleOCR-GPU не запускались (нет GPU) — LLM-контур оценён статически.
- Реальный TLS, сетевая сегментация, ACL Kafka/Redis/Postgres, внешние BDU/NVD/CMDB и СУБД заказчика локально не воспроизводились (помечено как ограничение).

### 2.3. Ограничения

- Не тестировались: TLS/HTTPS-конфигурация прод-сервера, доступ к реальным BDU/NVD/CMDB, нагрузочное/DoS-тестирование, физическая сегментация, аудит GPU-образов (vLLM/Paddle).
- CVSS-оценки в отчёте — экспертные (не сканированием), для приоритезации.
- Сканирование выполнено на незакоммиченном рабочем дереве; правки не вносились.

---

## 3. Результаты по этапам

### 3.1. SAST (Semgrep / Bandit / Ruff)

Semgrep — 7 находок:

| Правило | Файл:строка | Оценка |
|---|---|---|
| `dockerfile.security.missing-user` | `services/Dockerfile:34` | подтверждено (root) |
| `logging.logger-credential-leak` | `services/api_gateway/main.py:72` | подтверждено |
| `fastapi.security.wildcard-cors` | `services/api_gateway/main.py:82` | подтверждено |
| `logging.logger-credential-leak` | `services/shared/auth.py:95` | подтверждено |
| `logging.logger-credential-leak` | `services/llm_service/provider.py:169` | **ложное срабатывание** (логируются только счётчики токенов) |
| `sqlalchemy.avoid-sqlalchemy-text` | `services/shared/db.py:59,61` | **ложное срабатывание** (f-string по фиксированному внутреннему списку `_run_id_tables`, не пользовательский ввод) |

Ruff `--select S`: 419, из них 400 — `S101` (assert) в тестовых файлах; значимые: `S110`×5, `S310`×4, `S112`×4, `S105`×2, `S104`×1, `S106`×1, `S311`×1, `S314`×1.

Bandit: полный отчёт — `bandit.json`.

### 3.2. Зависимости (SCA)

**Python (pip-audit, `services/requirements.txt`)** — 27 уязвимостей в 2 пакетах:

- `pillow==12.2.0` — 25 advisories, исправлено в `12.3.0` (в основном разбор шрифтов/изображений: heap OOB, decompression bomb и др.).
- `ecdsa==0.19.2` — 2 advisories (Minerva timing attack, P-256), **исправления нет**. Приходит транзитивно (через `python-jose`/crypto-стек).

**JS (npm audit):**
- prod: `react-router`/`react-router-dom` — high (CSRF bypass в RSC-режиме; приложение использует клиентский `BrowserRouter`, эксплуатация маловероятна, но обновить).
- dev: + `nanoid` high, `postcss` moderate.

**Образы (Trivy):**
- `api-gateway`: **1 CRITICAL** — `libxml2` `CVE-2026-6653`; 94 HIGH (много без фикса: `util-linux`, `gnupg`, `libcurl`, `tesseract`, `libexpat`, `libtiff`, `libxml2`), 112 MEDIUM.
- `nginx`: **2 CRITICAL** — `libssl3`/`libcrypto3` `CVE-2026-31789` (fix `3.3.7-r0`); 37 HIGH, 58 MEDIUM.
- `trivy fs`: `Pillow` HIGH×10/MEDIUM×3, `react-router` HIGH, `glib` MEDIUM; 4 misconfig (см. 3.4).

> Рекомендация: обновить базовые образы (`python:3.12-slim`, `nginx:alpine`) и `Pillow` до `12.3.0`; зафиксировать диджесты базовых образов; по возможности перейти на `-slim`/`distroless` и убрать неиспользуемые пакеты (`gnupg`, `tesseract`, `poppler` — если OCR вынесен).

### 3.3. Секреты

Gitleaks по истории git (19 коммитов): **утечек не найдено**. `.env` в репозиторий не попадает (проверено `.gitignore`).

### 3.4. Конфигурация контейнеров (Trivy config/fs)

| ID | Severity | Файл | Суть |
|---|---|---|---|
| `DS-0002` | HIGH | `services/Dockerfile`, `frontend/Dockerfile` | нет `USER` — образ от root |
| `DS-0026` | LOW | оба Dockerfile | нет `HEALTHCHECK` |

Дополнительно: `vllm:latest` без пина; `bitnami/kafka:3.7` недоступен.

### 3.5. DAST

**ZAP baseline (nginx UI, пассивный + активный):** 0 FAIL, 10 WARN.
- Отсутствуют/некорректны: `Permissions-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`; статика кэшируется без `Cache-Control` для чувствительного контента; в JS-бандле раскрывается Unix-timestamp.
- `Server: nginx/1.27.5` — утечка версии (`server_tokens on`).

**ZAP API scan (OpenAPI gateway):** 0 FAIL, 2 WARN — отсутствуют `X-Content-Type-Options` и `Cross-Origin-Resource-Policy` в ответах API.

**Schemathesis (fuzzing, 41 операция, ~27k кейсов, 300 с):** 53 уникальных сбоя:
- **Server error (500) — 4:** `GET /admin/measures/candidates?status=<битый юникод/NUL>`, `GET /api/letters?limit=…&skip=-…`, `GET /documents?limit=…&skip=-…`, `PUT /api/letters/{id}/response` (тело `{}`).
- **Response violates schema / API rejected schema-compliant request — 8:** контракт OpenAPI не соответствует фактической валидации (например, `POST /api/templates/*` по спеке «проходит», по факту 422).
- **Invalid `Allow` header — 8**, **Undocumented HTTP status code — 33** (404/400/500 не описаны в спеке).

> Отдельно: `POST /api/auth/login` возвращал 401 при передаче Bearer-заголовка — ожидаемо (предупреждение `ignored_auth`).

---

## 4. Детальные находки

Severity: экспертные CVSS v3.1.

### F-01. JWT подписывается публично известным дефолтным секретом — **Critical (9.8)**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`

- **Где:** `services/docker-compose.yml:89` (`FSTEC_SECRET_KEY: ${FSTEC_SECRET_KEY:-dev-insecure-change-me}`), `services/.env.example:15` (`FSTEC_SECRET_KEY=dev-insecure-change-me`), `services/shared/auth.py` (HS256).
- **Суть:** при незаданном секрете токены подписываются известным значением; проверки `iss/aud` нет, отзыва токенов нет.
- **Подтверждение:** токен, сформированный `jwt.encode({'sub':'admin','role':'admin'}, 'dev-insecure-change-me', 'HS256')`, принят: `GET /api/auth/me` → `HTTP 200`, `role: admin`.
- **ASVS:** V6.2.3, V3.5.3, V2.10.4.
- **Рекомендация:** генерировать секрет на сервере (≥256 бит), обязать задавать `FSTEC_SECRET_KEY` (падать при старте, если значение пустое/дефолтное), убрать дефолт из compose и `.env.example`, ротация секрета, короткий TTL + refresh.

### F-02. Отсутствие авторизации на уровне объектов (IDOR) — **High (8.1)**
`AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

- **Где:** `services/api_gateway/main.py:341–702` (все `/documents/*`, `/api/letters/*`, `/reports/*` используют только `Depends(get_current_user)`); `services/shared/models.py:53` (`Document.created_by` не проверяется).
- **Суть:** любой аутентифицированный пользователь видит и меняет объекты всех пользователей.
- **Подтверждение:** пользователь `user2` (role `user`) получил список `GET /documents` с документом администратора, `GET /documents/1` → `200` (полные данные: текст, вложения, угрозы, IoC, уязвимости, ответ), `PUT /api/letters/1/response` → `200`, после чего администратор видит подменённый текст (`"HACKED by user2 (IDOR write)"`). При этом admin-эндпоинты защищены корректно (`GET /admin/measures` → `403`).
- **ASVS:** V4.1.1, V4.1.2, V4.2.1, V4.2.2.
- **Рекомендация:** ввести объектную авторизацию (проверка `created_by`/владельца либо явные права ролей) на всех операциях чтения/записи/экспорта/скачивания; централизовать в зависимости/сервисном слое; добавить тесты на кросс-пользовательский доступ.

### F-03. Bootstrap-пароль администратора в открытом виде в логах; bootstrap-запись не инвалидируется — **High (7.5)**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` (при доступе к логам/централизованному сбору)

- **Где:** `services/api_gateway/main.py:72`, `services/shared/auth.py:95–99`; `needs_setup` — `auth.py:103–104`; `BootstrapSecret` импортируется в `main.py:36`, но нигде не используется (запись не помечается `used`, не удаляется).
- **Подтверждение:** `docker logs fstec-api-gateway` содержит пароль в двух сообщениях (`Bootstrap password for user 'admin': …`, `Bootstrap admin password: …`); `GET /api/auth/status` → `{"needs_setup":true}` после успешного входа.
- **Следствие:** компрометация учётки админа через логи; бесконечный онбординг-экран; хранение хэша bootstrap-пароля после смены пароля.
- **ASVS:** V7.1.1, V7.2.1, V2.10.1, V2.2.1.
- **Рекомендация:** не логировать секреты; выдавать первичный пароль одноразово вне логов (env/secret-файл), форсировать смену при первом входе, помечать `used`/удалять `bootstrap_secrets` после установки пароля, реализовать endpoint настройки с проверкой сложности.

### F-04. Дефолтные/пустые креды инфраструктуры — **High (8.0)**
`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (внутренняя сеть)

- **Где:** `services/docker-compose.yml:35–37` (Postgres `${POSTGRES_USER:-fstec}/${POSTGRES_PASSWORD:-fstec}`), `redis` (нет `requirepass`), `kafka` (`PLAINTEXT`, `ALLOW_PLAINTEXT_LISTENER=yes`, нет ACL).
- **Подтверждение:** `psql -U fstec -d fstec` работает; `redis-cli PING` → `PONG` без пароля (`CONFIG GET requirepass` пусто); Kafka-слушатели — `PLAINTEXT://…:9092`.
- **ASVS:** V13.1.1, V13.2.1, V12.1.1, V12.1.2.
- **Рекомендация:** обязательные пароли из секрет-стора (не дефолт), `requirepass`/ACL для Redis, SASL/SSL + ACL для Kafka, минимальные права БД, сегментация сети, ротация.

### F-05. Compose не разворачивается: недоступный образ `bitnami/kafka:3.7` — **High (7.5)**
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`

- **Где:** `services/docker-compose.yml:3`.
- **Подтверждение:** `docker compose up` → `failed to resolve reference "docker.io/bitnami/kafka:3.7": not found`. Ранее использовавшийся `apache/kafka:3.7.0` доступен; также доступен `bitnamilegacy/kafka:3.7`.
- **Следствие:** деплой на чистом сервере падает (availability).
- **ASVS:** V14.1.1 (управление конфигурацией), процессное.
- **Рекомендация:** перейти на `apache/kafka:3.7.0` (с `KAFKA_*` env) либо `bitnamilegacy/kafka:3.7`, зафиксировать диджест.

### F-06. Wildcard CORS — **Medium (6.5)**
`AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N`

- **Где:** `services/api_gateway/main.py:80–85`.
- **Подтверждение:** `Origin: https://evil.example` → `access-control-allow-origin: *`; preflight разрешает `authorization,content-type` и все методы. `allow_credentials` не выставлен (cookie-сессии не утекают), но любой сторонний origin может инициировать запросы и читать ответы при наличии токена.
- **ASVS:** V14.5.3, V13.2.6.
- **Рекомендация:** список разрешённых origin, запрет `*` в prod, ужесточить методы/заголовки.

### F-07. Отсутствие security-заголовков и утечка версии — **Medium (5.3)**
`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`

- **Где:** `frontend/nginx.conf` (нет `add_header`), ответы API.
- **Подтверждение:** ZAP baseline/api WARN; `Server: nginx/1.27.5`. Нет `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, `COEP/CORP`.
- **ASVS:** V14.4.1–V14.4.7.
- **Рекомендация:** добавить заголовки в nginx (UI и прокси), включить `server_tokens off`, HSTS при HTTPS.

### F-08. Rate-limit не работает за прокси; неверный IP в аудите — **Medium (5.8)**
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H`

- **Где:** `services/api_gateway/main.py:43–64`; `docker-compose.yml:96` (`uvicorn` без `--proxy-headers`/`--forwarded-allow-ips`); `frontend/nginx.conf:14–15` выставляет `X-Real-IP`/`X-Forwarded-For`, которые приложение игнорирует.
- **Подтверждение:** 10 неудачных входов через nginx → 11-й `429` (лимит общий), а при прямом обращении к gateway — отдельный бакет. В `audit_log` IP входа через nginx записан как `172.18.0.6` (IP контейнера nginx), а не IP клиента.
- **Следствие:** один клиент исчерпывает лимит для всех (DoS аутентификации), аудит-лог недостоверен.
- **ASVS:** V11.1.4, V7.1.2, V2.2.1.
- **Рекомендация:** включить `--proxy-headers --forwarded-allow-ips=<nginx>`, доверять только доверенному прокси, учитывать IP из `X-Forwarded-For`; распределённый лимит (Redis) для нескольких реплик.

### F-09. Zip-bomb в парсерах ODT/DOCX/XLSX — **Medium (6.5)**
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

- **Где:** `services/shared/parsers/odt_parser.py:16–19` (и аналогично docx/xlsx) — нет лимита на суммарный распакованный размер/число записей.
- **Подтверждение:** ODT на 51 КБ распаковывается в `content.xml` ~50 МБ и парсится в строку 52 МБ (ratio ~1000×). Лимит загрузки 20 МБ не защищает от распакованного объёма.
- **ASVS:** V12.1.3, V12.3.1, V5.2.3.
- **Рекомендация:** ограничить суммарный распакованный размер и число файлов/энтри, стримить разбор, применять таймаут/лимит памяти в ingest-воркере.

### F-10. Невалидируемая пагинация: 500 и отсутствие верхней границы `limit` — **Medium (5.3)**
`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H`

- **Где:** `services/api_gateway/main.py` (`/documents`, `/api/letters` — `limit`/`skip` без `Query(ge=0, le=…)`).
- **Подтверждение:** `GET /documents?limit=1000&skip=-5` → `500`; `GET /documents?limit=100000000` → `200` (потенциальное исчерпание памяти).
- **ASVS:** V5.1.1, V5.1.3, V13.1.1.
- **Рекомендация:** `Query(..., ge=0, le=200)` для `skip`/`limit`, обработка ошибок БД, единый формат ошибок.

### F-11. Уязвимые зависимости — **Medium (6.5)**
- `Pillow 12.2.0` → `12.3.0` (25 advisories); `ecdsa 0.19.2` (без фикса — рассмотреть отказ/изоляцию); `react-router` 7.18.1 → ≥7.18.2; dev: `nanoid`, `postcss`.
- **ASVS:** V14.2.1–V14.2.3, V10.2.1.
- **Рекомендация:** обновить, включить регулярный SCA (pip-audit/npm audit/Trivy) в процесс релиза.

### F-12. Контейнеры запускаются от root, нет HEALTHCHECK — **Medium (5.5)**
- **Где:** `services/Dockerfile:34`, `frontend/Dockerfile`; Trivy `DS-0002`/`DS-0026`.
- **Рекомендация:** непривилегированный пользователь (`USER`), `read_only` ФС где возможно, `HEALTHCHECK`, drop capabilities.

### F-13. Публичные `docs`/`openapi.json`; `FSTEC_DISABLE_DOCS` не реализован — **Medium (5.3)**
- **Где:** `services/api_gateway/main.py:77` (`docs_url="/api/docs"`, `openapi_url="/api/openapi.json"`), переменная `FSTEC_DISABLE_DOCS` не читается.
- **Подтверждение:** оба эндпоинта → `200` без аутентификации.
- **ASVS:** V14.3.2, V13.1.5.
- **Рекомендация:** отключать docs/openapi в prod (`docs_url=None`), закрывать аутентификацией.

### F-14. Prompt injection в LLM-контур — **Medium (5.8)**
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N`

- **Где:** `services/llm_service/provider.py` (системные промпты, план из письма), `services/shared/generator/templated_reply.py`.
- **Суть:** текст письма управляет формированием блоков уязвимостей/мер без отделения «данных» от «инструкций»; возможна инъекция ложных CVE/мер в официальный ответ.
- **ASVS:** V11.1.1, V5.1.1 (по аналогии для LLM).
- **Рекомендация:** строгий вывод по схеме + валидация (BDU/NVD-проверка), изоляция инструкций от данных, allow-list формата, постпроверка человеком, ограничение «мер» (уже частично реализовано).

### F-15. Рассогласование переменных CMDB — **Medium (5.0)**
- **Где:** `services/shared/config.py:106` читает `CMDB_TOKEN`, тогда как `docker-compose.yml:155` и `.env.example` задают `CMDB_AUTH_TOKEN`.
- **Следствие:** аутентификация к CMDB заказчика молча не применяется (функциональный и потенциально security-дефект).
- **ASVS:** V14.1.1, V13.1.1.
- **Рекомендация:** согласовать имена переменных, добавить проверку обязательных env при старте.

### F-16. Инъекция в путь BDU — **Low (3.5)**
- **Где:** `services/security_service/bdu_client.py` (`_path_id` формирует путь из внешних данных).
- **Рекомендация:** строгая валидация/кодирование идентификаторов (allow-list `[A-Za-z0-9._-]`), таймауты и ограничение ответов.

### F-17. Неполный аудит-лог — **Low (3.0)**
- **Где:** `_audit(...)` в `main.py` не всегда получает `request` → `ip_address` пустой (видно в `audit_log`: `upload`, `update_response` без IP).
- **ASVS:** V7.1.2, V7.2.1.
- **Рекомендация:** прокидывать `Request` во все мутирующие операции, логировать user/ip/объект/результат.

### F-18. `needs_setup` всегда `true` — **Low (3.0)** (часть F-03)
- **Где:** `auth.py:103–104`; bootstrap-запись не удаляется. Влияние: UI-онбординг, остаточный хэш.

### F-19. CI без сканов безопасности — **Low (2.0)**
- **Где:** `.github/workflows/build-linux-rpm.yml` — нет gitleaks/trivy/semgrep/pip-audit. (По решению заказчика в CI не внедряем; фиксируется как рекомендация.)

### F-20. `vllm:latest` без пина — **Low (3.0)**
- **Где:** `docker-compose.yml:50`. Риск supply-chain/несовместимости. Рекомендация: фиксировать тег/диджест.

### F-21. Отсутствие XXE в ODT — **Info (проверено, не подтверждено)**
- **Где:** `services/shared/parsers/odt_parser.py:19` (`xml.etree.ElementTree`).
- **Проверка:** внешняя сущность `SYSTEM "file:///etc/passwd"` → `undefined entity`, раскрытия нет; «billion laughs» (внутренние сущности) также отклоняется. **Гипотеза об XXE не подтвердилась.** Актуален только zip-bomb (F-09).

### F-22. `text(f"...")` в `db.py` — **Info (ложное срабатывание)**
- f-string подставляется из фиксированного списка `_run_id_tables`, пользовательского ввода нет.

### F-23. Общий объём 5xx по fuzzing — **Info**
- 4 воспроизводимых 500 (F-10 + пустое тело `PUT response`) свидетельствуют об отсутствии глобального обработчика ошибок. Рекомендация: middleware обработки исключений + единый JSON-формат ошибок без деталей стека.

---

## 5. Матрица OWASP ASVS 4.0.3 (L2, фрагмент)

| Раздел ASVS | Статус | Комментарий |
|---|---|---|
| V1 Архитектура | Частично | Нет модели объектной авторизации, не документированы границы доверия |
| V2 Аутентификация | Не соответствует | F-01, F-03, F-08 |
| V3 Управление сессией/токенами | Частично | JWT без отзыва, подпись дефолтным секретом (F-01) |
| V4 Контроль доступа | **Не соответствует** | IDOR read/write (F-02) |
| V5 Валидация/кодирование | Частично | Пагинация 500, zip-bomb (F-09, F-10) |
| V6 Криптография | Частично | F-01; зависимости (F-11) |
| V7 Обработка ошибок и логи | Не соответствует | Пароль в логах, пустой IP в аудите (F-03, F-17) |
| V8 Защита данных | Частично | Нет шифрования данных БД/бэкапов на уровне приложения |
| V9 Коммуникации | Не проверено локально | TLS/HTTPS прод не воспроизводился |
| V10 Вредоносный код | Частично | SCA (F-11), пин образов (F-20) |
| V11 Бизнес-логика | Частично | Prompt injection (F-14) |
| V12 Файлы и ресурсы | Частично | Zip-bomb (F-09), валидация magic OK |
| V13 API и веб-сервисы | Частично | CORS, docs, 5xx, rate-limit (F-06, F-08, F-13) |
| V14 Конфигурация | Не соответствует | Root, заголовки, дефолтные креды, kafka-образ (F-04, F-05, F-07, F-12) |

---

## 6. Проверенные гипотезы

| Гипотеза | Итог |
|---|---|
| XXE в ODT-парсере | **Не подтверждена** (ElementTree не разрешает сущности) |
| SQL-инъекция через `text(f"...")` | **Не подтверждена** (фиксированный список) |
| IDOR / нет объектной авторизации | **Подтверждена** (чтение + запись чужого документа) |
| Пароль bootstrap в логах | **Подтверждена** (дважды в логах) |
| `needs_setup` всегда true | **Подтверждена** |
| Wildcard CORS | **Подтверждена** |
| Публичные docs/openapi | **Подтверждена** |
| Rate-limit обходится/общий за прокси | **Подтверждена** (IP = 172.18.0.6) |
| Zip-bomb в парсерах | **Подтверждена** |
| Подделка JWT при дефолтном секрете | **Подтверждена** |
| Утечки секретов в git | **Не обнаружено** (gitleaks) |

---

## 7. Приоритезированный план устранения

**Немедленно (до вывода на сервер):**
1. F-01 — обязательный `FSTEC_SECRET_KEY` (≥256 бит), убрать дефолт; отказ старта при небезопасном значении.
2. F-02 — объектная авторизация на всех операциях с документами/письмами/отчётами.
3. F-03 — не логировать пароли; одноразовая выдача первичного пароля вне логов; инвалидировать `bootstrap_secrets`.
4. F-04 — задать пароли Postgres/Redis, включить auth для Kafka; проверить закрытость портов (кроме nginx).
5. F-05 — исправить образ Kafka в compose.

**Ближайший релиз:**
6. F-06, F-07, F-08, F-13 — CORS-allow-list, security-заголовки, `--proxy-headers`, отключить docs в prod.
7. F-09, F-10 — лимиты распаковки и пагинации; глобальный обработчик ошибок.
8. F-11, F-12, F-20 — обновить зависимости, `USER`/`HEALTHCHECK`, пин образов.
9. F-15, F-16 — согласовать env CMDB, валидировать пути BDU.

**Планово:**
10. F-14 — усилить валидацию LLM-вывода.
11. F-17, F-19 — аудит-лог и (опционально) сканы в CI.
12. Перепроверить ASVS L2 после исправлений; отдельно — TLS/сегментация/БД заказчика на стенде.

---

## 8. Приложение. Артефакты

Каталог: `docs/audit/2026-09-21/`

| Файл | Содержание |
|---|---|
| `semgrep.sarif` | SAST (7 находок) |
| `bandit.json` | SAST Bandit |
| `ruff-security.json` | Ruff security-rules |
| `summary_stage1.txt` | сводка SAST |
| `pip-audit.json`, `summary_deps.txt` | SCA Python |
| `npm-audit.json`, `npm-audit-prod.json` | SCA JS |
| `gitleaks.json` | секреты (`[]`) |
| `trivy-gateway.json`, `trivy-nginx.json`, `trivy-fs.json`, `trivy-config.json`, `summary_trivy.txt` | контейнеры/FS/конфиги |
| `zap-baseline.html/.json`, `zap-api.html/.json`, `zap.yaml` | DAST ZAP |
| `schemathesis.txt` | DAST fuzzing |

### Ключевые команды воспроизведения

```powershell
# Стек (Kafka заменена на доступный образ через override)
docker compose -p fstec-audit -f docker-compose.yml -f <override> up -d postgres redis kafka api-gateway nginx

# Подделка JWT дефолтным секретом
docker exec fstec-api-gateway python -c "from jose import jwt; print(jwt.encode({'sub':'admin','role':'admin'},'dev-insecure-change-me',algorithm='HS256'))"

# IDOR (после создания user2)
curl -H "Authorization: Bearer <user2>" http://127.0.0.1:8666/documents/1
curl -X PUT -H "Authorization: Bearer <user2>" -H "Content-Type: application/json" -d '{"content":"x"}' http://127.0.0.1:8666/api/letters/1/response

# Прокси/аудит IP
docker exec -e PGPASSWORD=fstec fstec-postgres psql -U fstec -d fstec -c "SELECT username,action,ip_address FROM audit_log ORDER BY id DESC LIMIT 5;"
```

> По завершении аудита тестовый контур `fstec-audit` останавливается; артефакты сохранены.

---

## 9. Статус устранения (2026-09-21, после аудита)

Исправления внесены в код; регрессия `pytest tests -q` — **130 passed**, повторная
проверка эксплойтов — **22/22 OK**, сборка образов `api-gateway` и `nginx` — успешно,
compose-конфиг валиден, контейнеры работают под непривилегированным пользователем.

| ID | Статус | Что сделано |
|---|---|---|
| F-01 | Устранено | `shared/config.py`: в prod `FSTEC_SECRET_KEY` обязателен (>=32 симв.), известные дефолты запрещены (fail-fast `RuntimeError`); в dev — эфемерный случайный секрет. В compose `FSTEC_SECRET_KEY: ${FSTEC_SECRET_KEY:?...}`. Подделка токена дефолтным секретом → 401. |
| F-02 | Устранено | `api_gateway/main.py`: helper `_owned_document` (404 для чужого документа) и `_scoped_documents`; покрыты `/documents/{id}`, `/reports/*`, `/reply/generate`, все `/api/letters/*`, обновление уязвимостей, экспорт/скачивание; списки и статистика фильтруются по владельцу (admin видит всё). |
| F-03 | Устранено | `shared/auth.py`: пароль не логируется; берётся из `FSTEC_BOOTSTRAP_PASSWORD` либо пишется в `data/bootstrap_password.txt` (0600); `mark_bootstrap_used` после первого входа. |
| F-04 | Частично | Postgres/Redis: пароли обязательны (`:?`), Redis `requirepass` + volume; порты БД/Redis/Kafka привязаны к `127.0.0.1`. Kafka остаётся PLAINTEXT в изолированной compose-сети (SASL — в бэклог). |
| F-05 | Устранено | Kafka: `bitnamilegacy/kafka:3.7` (образ доступен), конфиг проверен `docker compose config`. |
| F-06 | Устранено | CORS — allow-list `FSTEC_CORS_ORIGINS` (в prod по умолчанию пусто; в dev — localhost:5173). |
| F-07 | Устранено | `frontend/nginx.conf`: `server_tokens off` + CSP/HSTS-набор заголовков; в FastAPI — middleware security-заголовков. |
| F-08 | Устранено | uvicorn `--proxy-headers --forwarded-allow-ips *`; IP клиента учитывает `X-Forwarded-For`. |
| F-09 | Устранено | `_xml_guard.py`: лимиты распакованного размера проверяются по заголовкам ZIP до чтения + лимит числа файлов; guard применён и к ODT. ODT-бомба (50 МБ content.xml) отклоняется. |
| F-10 | Устранено | Пагинация: `Query(ge=0)` для `skip`, `Query(ge=1, le=200)` для `limit` на `/documents` и `/api/letters`. |
| F-11 | Устранено (Python частично) | `Pillow==12.3.0`; `npm audit fix` → 0 уязвимостей (react-router 7.18.4, nanoid 3.3.18, postcss 8.5.16); базовые образы: `apt-get upgrade` / `apk upgrade`. `ecdsa 0.19.2` — без апстрим-фикса, не используется (только HS256), принято как остаточный риск. |
| F-12 | Устранено | `services/Dockerfile`: пользователь `appuser` (uid 10001) + `HEALTHCHECK`; frontend — `nginx-unprivileged` (uid 101); healthcheck gateway. |
| F-13 | Устранено | `FSTEC_DISABLE_DOCS` (в prod=1): `/api/docs` и `/api/openapi.json` → 404. |
| F-14 | Снижено | `templated_reply.py`: валидация CVE/BDU/CVSS/severity (allow-list regex, clamp 0..10) для внешних данных; отключены плейсхолдеры `{{...}}` в рендере. Полная защита от prompt-injection — бэклог. |
| F-15 | Устранено | `shared/config.py` читает `CMDB_AUTH_TOKEN` (fallback `CMDB_TOKEN`). |
| F-16 | Устранено | `bdu_client._path_id`: строгая проверка формата `^\d{4}-\d{4,}$`; инъекция в путь → пусто. |
| F-17 | Устранено | IP клиента через `ContextVar` (middleware) — все `_audit` пишут IP; исправлена потеря аудит-записей (commit внутри `_audit`). |
| F-18 | Устранено | `needs_setup` = есть неиспользованный bootstrap-секрет; после входа — False. |
| F-19 | Принято | Сканы в CI не внедряются (решение заказчика). |
| F-20 | Устранено | `vllm/vllm-openai:v0.9.0` (пин вместо `latest`). |
| F-21–F-23 | Инфо | XXE в ODT не эксплуатируется; `text(f"...")` — ложное; глобальный обработчик исключений (500 JSON) добавлен. |

### Повторная проверка (эксплойты)
- подделка JWT дефолтным секретом → `401`; в prod без секрета сервис не стартует;
- IDOR: `user2` читает/меняет чужой документ → `404`;
- `needs_setup` → `False` после входа; пароль bootstrap — в файле 0600, не в логе;
- ODT zip-bomb отклоняется; инъекция в путь BDU нейтрализована; пагинация → `422`;
- CORS без wildcard; security-заголовки присутствуют; docs закрыты (`404`);
- контейнеры: gateway `uid=10001`, nginx `uid=101`, healthcheck `healthy`.

### 9.1. Перепроверка сканерами после исправлений (реверификация)

Полный повторный прогон — `docs/audit/2026-09-21/reverify/summary_reverify.txt`, артефакты в
`docs/audit/2026-09-21/reverify/`. Сводка дельт против базового аудита:

| Инструмент | База | После правок | Комментарий |
|---|---|---|---|
| pip-audit | 27 (2 пакета) | **2 (1 пакет)** | закрыт `pillow 12.3.0`; `ecdsa 0.19.2` — фикса нет (принятый риск) |
| npm audit | prod 2 / всего 4 | **0 / 0** | react-router 7.18.4, nanoid 3.3.18, postcss 8.5.16 |
| semgrep | 7 | 5 (0 true-positive) | закрыты missing-user, wildcard-cors, утечки пароля в логах; остались FP/инфо |
| bandit | — | новых нет | urllib/bind/HF-pin — инфо; XXE B314 не воспроизводится |
| trivy gateway image | 1C/94H/112M | 1C/84H/109M | `libxml2 CVE-2026-6653` — upstream-фикса ещё нет (остаточный риск) |
| trivy nginx image | **2C/37H/58M** | **0** | сменён базовый образ + `apk upgrade` |
| trivy fs | 15 | **1 MEDIUM** | `glib` (Rust/Tauri, сервером не используется) |
| trivy misconfig (fs/config) | 4 | **0** | `USER` + `HEALTHCHECK` в обоих Dockerfile |
| schemathesis | 53 сбоя, **4×500** | 47 сбоев, **0×500** | см. ниже про OverflowError |
| gitleaks/секреты | 0 | 0 | |

**Дополнительно найдено и устранено при реверификации (составная часть F-10/F-23):**
- Числовые параметры порядка 10^25 (`skip`, `id` в пути, `threat_type_id`) вызывали `500`
  (переполнение SQLite INTEGER). Исправлено: `Query(le=…)` для `skip`/`threat_type_id`
  и глобальный обработчик `OverflowError` → `422`. Подтверждено на живом контуре и в
  schemathesis: серверных ошибок не осталось.
- Аудит-лог терял записи для ручек, вызывавших `_audit` после `db.commit()` (например,
  `/admin/measures`) — `_audit` теперь коммитит запись сама; IP во всех записях.

Уровень ASVS L2 после реверификации: V4, V5, V7, V12, V13 (по выявленным пунктам) —
**соответствует**; V2, V3, V6, V8, V10, V11, V14 — частично; V1, V9 — требуют
документирования отдельно (архитектура, TLS на прод-стенде). Остаточные риски: Kafka
PLAINTEXT в изолированной compose-сети, `ecdsa 0.19.2`, `libxml2 CVE-2026-6653` (без
upstream-фикса), prompt injection (снижен валидацией вывода), шифрование at-rest/TLS
— проверяются/реализуются на прод-стенде.
