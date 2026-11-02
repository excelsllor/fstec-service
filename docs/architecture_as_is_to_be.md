# Архитектурная документация AS-IS / TO-BE

Система интеллектуальной обработки входящих документов с функциями индикаторного анализа и оценки кибербезопасности.
ТЗ: `TEKhNIChESKOE_ZADANIE_po_proektu_LGTU.docx`, п. 6 «Требования к документации», п. 3.1 «Архитектура».

---

## 1. AS-IS (текущая реализация — микросервисы)

### 1.1 Состав
| Компонент | Стек | Назначение |
|---|---|---|
| api-gateway | Python 3.10 / FastAPI | :8666, auth (JWT/bcrypt), upload, документы, отчёты, reply (ТЗ 2.6) + совместимость `/api/letters/...` |
| ingest-service | python-docx/olefile/openpyxl/pdfplumber/striprtf | Парсинг PDF/DOC/DOCX/ODT/XLSX/RTF/TXT/HTML/EML, OCR сканов PDF (tesseract/paddle) |
| llm-service | HeuristicProvider / VLLMProvider (Qwen3, OpenAI API) | Классификация, NER (орг/сроки/контакты), саммари ≤500 симв |
| security-service | NVD API v2 / bdu.fstec.ru / CMDB-mock | CVSS, версионный matching, SLA, роутинг (InfoSec), ретраи · кэш Redis |
| reporting-service | python-docx | Карточка индикаторов `Report_[имя]_[дата].docx`, проект ответа (DOCX) |
| Шина событий | memory \| sqlite \| Kafka (топики uploaded/parsed/analyzed/assessed) | Асинхронный конвейер (ТЗ 3.1) |
| Хранилище | SQLite (dev) / PostgreSQL (prod, конфиг) | Данные писем, IOC, угроз, уязвимостей, шаблонов, аудит |
| LLM (prod) | vLLM + Qwen3-14B (NVIDIA), локально llama.cpp Vulkan | Классификация/анализ (ТЗ 2.3) |
| Frontend | React + TypeScript + Vite + MUI | Web-интерфейс оператора/администратора (:5173 → :8666) |
| Desktop | Tauri v2 (webview) | Десктоп-оболочка без встроенного бэкенда |

> Legacy-монолит `backend/` (FastAPI :8765 + PyInstaller sidecar) **удалён** в рамках
> WS-2; резервная копия — `%USERPROFILE%\fstec-legacy-backup-2026-09-08`.

### 1.2 Модули (каталог `services/`)
- `api_gateway/main.py` — FastAPI: bootstrap-auth, `/upload` (лимиты 20 МБ / 10 файлов, magic-bytes), `/documents`, `/reports/{id}/download(_raw)`, `/reply/generate`, `/api/letters/...` (совместимость)
- `ingest_service/worker.py` — обработка `documents.uploaded`: парсинг всех вложений, OCR, публикация `document.parsed`
- `llm_service/provider.py`, `llm_service/worker.py` — `LLMProvider` (heuristic|vllm), классификация + NER + саммари
- `security_service/` — клиенты NVD v2 / BDU, CMDB-коннектор, версионный matching, SLA, ретраи + кэш Redis
- `reporting_service/` — генерация карточки индикаторов и проекта ответа (DOCX)
- `shared/` — config, db (ORM 13 таблиц), bus (memory/sqlite/kafka), parsers, extractors (IoC, NER, vuln), worker (routing)
- `tests/` — pytest (E2E всех форматов, конвейер, лимиты, конкурентность); `tools/services_smoke.py` — живой смоук

### 1.3 REST API (совместимость + ТЗ 2.6)
- `POST /api/auth/login`, `GET /api/auth/me`, `GET /api/auth/status`
- `POST /api/letters/upload`, `GET /api/letters`, `GET /api/letters/stats`, `GET /api/letters/{id}`
- `GET /api/letters/{id}/export/{type}` + `/docx` (emails, ip_addresses, domains, ioc_indicators)
- `PUT /api/letters/{id}/response`, `GET/PUT/DELETE /api/users`, `GET/POST/PUT/DELETE /api/templates/...`, `DELETE /api/letters/{id}`
- `POST /upload`, `GET /documents`, `GET /documents/{id}`, `GET /reports/{id}/download`, `GET /reports/{id}/download_raw`, `POST /reply/generate`

### 1.4 Схема (AS-IS)
```
[Браузер / Tauri]
       │ HTTP (JWT, ≤20 МБ, ≤10 файлов)
       ▼
[API Gateway FastAPI :8666]
  ├─ auth / users / templates / letters / reports / reply
  ├─ POST /upload ──► [шина: Kafka | sqlite | memory]
  ▼
[ingest-service]  парсеры форматов + OCR ──► document.parsed
  ▼
[llm-service]  heuristic | vllm (Qwen3) · regex-first → document.analyzed
  ▼
[security-service]  NVD v2 · bdu.fstec.ru · CMDB · matching · SLA → security.assessed
  ▼
[reporting-service]  карточка индикаторов + проект ответа (DOCX)
        ▼
[API Gateway]  GET /reports/{id}/download(_raw) · /reply/generate
```

### 1.5 Ограничения текущей реализации (что проверяется на внедрении)
1. BDU: TLS-сертификат bdu.fstec.ru локально не проходит (client verify) — перепроверить на целевом сервере.
2. NVD/BDU/CMDB работают в режиме `mock` в CI/локально; live-режим требует сети и API-ключа.
3. vLLM — серверный Linux/NVIDIA; локально (Windows+AMD) используется llama.cpp Vulkan для доводки промптов.
4. PaddleOCR GPU, KPI (OCR ≤2с, ≤5с/≤3с, 500+ писем/час) — измерить на целевой конфигурации.
5. Конвейер поверх Kafka проверен локально (докер-контейнеры); at-least-once — идемпотентность обработчиков при внедрении.

---

## 2. TO-BE (целевая микросервисная архитектура)

### 2.1 Принципы
- **Микросервисы** по бизнес-функциям (ТЗ 3.1), каждый масштабируется независимо.
- **Асинхронная обработка** через **Kafka** (событийная шина между сервисами).
- **API Gateway** — единая точка входа, аутентификация, маршрутизация, ограничение по размеру файлов.
- **Синхронные REST-вызовы** Gateway → сервисы для чтения; **асинхронные события Kafka** для обработки.
- Общее хранилище: **PostgreSQL** (операционные данные) + **Redis** (кэш уязвимостей, состояния, rate-limit).
- LLM-сервис: **Qwen3-14B-Q4** (GGUF) через **vLLM** (OpenAI-совместимый API), абстрактный LLMProvider.
- Обработка документов: **regex-first** для индикаторов + **чанкинг ≤4k токенов** + **continuous batching** в vLLM.

### 2.2 Сервисы

#### 2.2.1 api-gateway (FastAPI)
- Приём запросов от браузера/Desktop (REST).
- Аутентификация (JWT), авторизация (роли оператор/админ), аудит действий.
- REST API по ТЗ 2.6: `POST /upload`, `GET /documents`, `GET /documents/{id}`,
  `GET /reports/{id}/download`, `GET /reports/{id}/download_raw`, `POST /reply/generate`.
- Обратная совместимость со старыми путями `/api/letters/...`.
- Лимиты: файл ≤20 МБ, пакет ≤10 файлов (ТЗ 2.1), drag-and-drop (ТЗ 4.4).
- Статику/SPA отдаёт frontend-контейнер (nginx).

#### 2.2.2 ingest-service (парсинг + OCR)
- Приём файлов (из Gateway), валидация форматов. + Tesseract OCR (ru) для сканов (ТЗ 2.2).
- Парсеры: PDF (pdfplumber), DOC/DOCX, RTF, XLSX, ODT, TEXT (перенос из монолита).
- Извлечение текста ≤2с (ТЗ 4.1); сохранение текста + метаданных (имя, дата, сотрудник).
- Публикует событие `document.parsed` в Kafka.

#### 2.2.3 llm-service (оркестратор LLM)
- Классификация письма (ТЗ 2.3.1).
- NER: организации, сроки, контакты; IPv4/IPv6+CIDR, FQDN, email (+плюс-теги); ссылки
  NVD/BDU, CVE, ПО с версиями (ТЗ 2.3.2). Сетевые индикаторы — **строгий regex + LLM-валидация**.
- Саммари ≤500 символов (ТЗ 2.3.3).
- Chunking ≤4k токенов, батч, vLLM. Время обработки ≤5с (ТЗ 4.1).
- Публикует `document.analyzed`.

#### 2.2.4 security-service (Security Posture Analyzer)
- Клиент **NVD API v2** и **bdu.fstec.ru**: CVSS, CPE, уязвимый диапазон версий, ссылка на патч (ТЗ 2.4).
- **CMDB-коннектор**: REST/SQL-запрос к БД инвентаризации Заказчика (мок в dev, реальный конфиг на внедрении).
- **Версионный matching**: CPE/названия ПО vs инвентаризационная база → Match (ТЗ 2.4).
- **Приоритизация**: при Match SLA → «Критический», маршрутизация в отдел InfoSec (ТЗ 2.4).
- **Рекомендация**: «Обновить {Product} с {current_ver} до {fixed_ver}» (ТЗ 2.4).
- Ретраи ≤3 с экспоненциальной задержкой; при полной недоступности — уведомление оператора + ручной режим (ТЗ 4.2).
- Публикует `security.assessed`.

#### 2.2.5 reporting-service (Reporting)
- Карточка индикаторов (ТЗ 2.5.1): шапка + Раздел 1 (IP, IPv4/IPv6, без дублей) + Раздел 2
  (домены с корневым) + Раздел 3 (email) + Раздел 4 (таблица уязвимостей: CVE, CVSS, ПО,
  текущая/целевая версия, статус угрозы). Именование `Report_[Исходное_имя]_[YYYY-MM-DD].docx`.
- Проект ответа (ТЗ 2.5.2): при угрозе — требование/рекомендация обновления (без раскрытия
  архитектуры Заказчика); при отсутствии угрозы — уведомление о том, что ПО не подвержено риску.
- Генерация DOCX ≤3с (ТЗ 4.1).

#### 2.2.6 kafka / redis / postgres / cmdb-mock
- **Kafka**: топики `documents.uploaded`, `document.parsed`, `document.analyzed`,
  `security.assessed`, `report.ready`, `reply.generated`, `audit.events`.
- **Redis**: кэш ответов NVD/BDU (ускорение ≤15с проверки уязвимости), состояния обработки, rate-limit.
- **PostgreSQL**: данные писем, IOC, уязвимостей, пользователей, шаблонов, аудит, генераций.
- **CMDB-mock** (dev): заглушка REST-эндпоинта инвентаризации для тестов.

### 2.3 Схема (TO-BE)
```
[Браузер / Desktop]
        │ HTTPS (JWT, м.б. ≤20МБ, ≤10 файлов, drag-drop)
        ▼
[API Gateway (FastAPI)]
  ├── REST чтение/запись ───────────────► [PostgreSQL]
  ├── POST /upload ──► [Kafka: documents.uploaded]
  ▼
[ingest-service]  парсеры + Tesseract OCR ──► Kafka: document.parsed
        ▼
[llm-service]  Qwen3-14B-Q4 (vLLM) · regex-first · chunk ≤4k · batch
        │   классификация / NER / саммари
        ▼ Kafka: document.analyzed
[security-service]  NVD API v2 · bdu.fstec.ru · CMDB-коннектор · matching · SLA
        ▼ Kafka: security.assessed
[reporting-service]  карточка индикаторов + проект ответа (DOCX ≤3с)
        ▼ Kafka: report.ready / reply.generated
[API Gateway]  GET /reports/{id}/download · /reports/{id}/download_raw
        ▼
[Браузер/Desktop]
```
Вспомогательное: Redis (кэш/состояния), PostgreSQL (хранилище), CMDB-mock (dev).

### 2.4 Поток обработки документа (сквозной сценарий)
1. Оператор загружает письмо с вложениями через Gateway (drag-drop / REST) → файлы в объектное хранилище (FS), запись в БД, событие `documents.uploaded`.
2. ingest-service читает файлы, парсит (≤2с), при необходимости OCR (Tesseract ru), сохраняет текст+метаданные, шлёт `document.parsed`.
3. llm-service: regex-first извлекает индикаторы (IP/домен/email/CVE/BDU/ПО+версии), LLM делает классификацию, NER (орг/сроки/контакты), валидацию индикаторов, саммари ≤500 симв. → `document.analyzed`.
4. security-service: для найденных CVE/BDU запрашивает NVD/BDU (ретраи до 3, кэш Redis), сверяет с CMDB (matching версий), при совпадении ставит SLA «Критический» + маршрутизация InfoSec + заметку «Обновить X c a до b» → `security.assessed`.
5. reporting-service: генерирует Карточку индикаторов (≤3с) + проект ответа → БД.
6. Оператор/админ просматривает, при необходимости правит (ручная корректировка), скачивает DOCX / файлы IOC, отправляет `POST /reply/generate` при необходимости.

---

## 3. Статус миграции AS-IS → TO-BE
1. **Сделано**: монолит выделен в микросервисы (`services/`), шина событий (memory/sqlite/kafka), Gateway с новой REST-схемой (ТЗ 2.6), OCR, llm-сервис (heuristic/vllm), security-сервис (NVD/BDU/CMDB-mock), reporting (карточка индикаторов + ответ).
2. **Внедрение**: PostgreSQL вместо SQLite, live-режимы NVD/BDU/CMDB, vLLM (Qwen3-14B) на сервере с NVIDIA, KPI-замеры, PaddleOCR GPU, идемпотентность обработчиков Kafka (at-least-once).
3. Обратная совместимость: endpoint'ы `/api/letters/...` работают в Gateway (перенесены при миграции).

## 4. Ограничения и допущения
- CMDB Заказчика в dev недоступен — используется CMDB-mock; реальная БД подключается конфигом на внедрении.
- BDU/NVD требуют доступа в сеть (по решению Заказчика интернет необходим).
- GPU: RTX 4090 24 ГБ (одна), Qwen3-14B-Q4 через vLLM; KPI 5с/500+ обеспечиваются чанкингом ≤4k + ботлингом.
- Резерв по производительности: 2× A10/4090 при недоборе KPI.