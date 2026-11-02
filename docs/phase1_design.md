# Схема событий Kafka, интерфейсы сервисов и модель данных

ТЗ: `TEKhNIChESKOE_ZADANIE_po_proektu_LGTU.docx`, п. 3.1 (микросервисы + очередь), п. 2.6 (REST).

---

## 1. Kafka-топики и события

Все события — JSON, ключ сообщения = `document_id` (string), партиционирование по документу
гарантирует упорядоченность обработки одного документа.

### 1.1 Перечень топиков

| Топик | Продюсер | Потребитель | Содержимое |
|---|---|---|---|
| `documents.uploaded` | api-gateway | ingest-service | Документ загружен, файлы сохранены |
| `document.parsed` | ingest-service | llm-service | Текст извлечён (парсинг+OCR), метаданные |
| `document.analyzed` | llm-service | security-service | Классификация, NER, IoC, саммари |
| `security.assessed` | security-service | reporting-service | Результаты NVD/BDU + CMDB-matching + SLA |
| `report.ready` | reporting-service | api-gateway | Карточка индикаторов готова |
| `reply.generated` | reporting-service | api-gateway | Проект ответа готов |
| `audit.events` | все сервисы | audit-consumer (gateway) | Журнал действий пользователей |

Параметры топиков:
- retention: `documents.*`/`document.*`/`security.*`/`report.*`/`reply.*` — 7 дней (компактная история не нужна).
- `audit.events` — **compact + infinite retention** (обязательное хранение журнала аудита, ТЗ 4.3).

### 1.2 Схемы событий

```jsonc
// documents.uploaded
{
  "event": "documents.uploaded",
  "document_id": "doc_9-104",
  "user_id": 1,
  "filename": "9-104.pdf",
  "file_path": "/data/uploads/9-104/9-104.pdf",
  "size": 188167,
  "mime": "application/pdf",
  "attachments": [
    {"filename": "Проект мер № 9-104.docx", "path": "/data/uploads/9-104/proekt.docx", "size": 30451}
  ],
  "uploaded_at": "2026-09-07T10:00:00Z"
}

// document.parsed
{
  "event": "document.parsed",
  "document_id": "doc_9-104",
  "text": "... извлечённый текст ...",
  "ocr_used": false,
  "parse_errors": [],
  "parsed_at": "2026-09-07T10:00:02Z"
}

// document.analyzed
{
  "event": "document.analyzed",
  "document_id": "doc_9-104",
  "classification": "hacker_group_letter",
  "summary": "Краткое саммари до 500 символов...",
  "entities": { "organizations": [], "deadlines": [], "contacts": [] },
  "iocs": {
    "ip_addresses": ["1.2.3.4", "2001:db8::1", "192.168.0.0/24"],
    "domains": ["evil.example.com", "example.com"],
    "emails": ["boss@example.com", "tag+plus@example.com"],
    "cve": ["CVE-2026-1234"],
    "bdu": ["BDU:2026-01234"],
    "software": [{"name": "OpenSSL", "version": "1.1.1k"}]
  },
  "llm_validation": { "validated": true, "corrections": [] },
  "analyzed_at": "2026-09-07T10:00:05Z"
}

// security.assessed
{
  "event": "security.assessed",
  "document_id": "doc_9-104",
  "vulnerabilities": [
    {
      "cve_id": "CVE-2026-1234",
      "cvss_score": 9.1,
      "cpe": "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*",
      "affected_range": "<=1.1.1k",
      "fixed_version": "1.1.2",
      "patch_url": "https://www.openssl.org/news/security.html",
      "match": true,
      "current_version": "1.1.1k",
      "target_version": "1.1.2",
      "status": "critical"
    }
  ],
  "sla": "critical",
  "routing": "infosec",
  "recommendation": "Обновить OpenSSL с 1.1.1k до 1.1.2",
  "assessed_at": "2026-09-07T10:00:20Z"
}

// report.ready
{
  "event": "report.ready",
  "document_id": "doc_9-104",
  "report_path": "/data/reports/Report_9-104.pdf_2026-09-07.docx",
  "generated_at": "2026-09-07T10:00:22Z"
}

// reply.generated
{
  "event": "reply.generated",
  "document_id": "doc_9-104",
  "reply_path": "/data/reports/Reply_9-104_2026-09-07.docx",
  "summary": "Требование срочного обновления...",
  "generated_at": "2026-09-07T10:00:22Z"
}
```

### 1.3 Retry / DLQ
- Потребители идемпотентны (по `document_id`), offset-коммит после успешной обработки.
- При сбое: 3 ретрая с экспоненциальной задержкой (1с, 2с, 4с), затем событие в DLQ-топик
  `documents.failed` + уведомление оператора (ТЗ 4.2: «уведомление оператора и перевод в ручной режим»).

### 1.4 OCR-провайдер (Фаза 2.5)
- Интерфейс: `ocr_pdf_bytes(content, lang) -> (text, errors)` в `shared/parsers/ocr.py`.
- Выбор движка: `FSTEC_OCR_ENGINE=auto|paddle|tesseract`, устройство `FSTEC_OCR_DEVICE=gpu|cpu`.
- `auto`: PaddleOCR (GPU, ru) → fallback Tesseract (CPU) при недоступности/пустом результате.
- Распознавание отрабатывает в ingest-сервисе; результат передаётся в `document.parsed` (поле `ocr_used`, `parse_errors`).

---

## 2. Интерфейсы сервисов

### 2.1 api-gateway — REST (внешний контур, ТЗ 2.6)

| Метод | Путь | Назначение | Аутентификация |
|---|---|---|---|
| POST | `/upload` | Загрузка файла(ов) для обработки (≤20МБ, ≤10 файлов) | JWT, роли op/admin |
| GET | `/documents` | Список обработанных документов с пагинацией | JWT |
| GET | `/documents/{id}` | Метаданные и статус обработки | JWT |
| GET | `/reports/{id}/download` | Скачивание сгенерированного DOCX-отчёта | JWT |
| GET | `/reports/{id}/download_raw` | Скачивание оригинального загруженного файла | JWT |
| POST | `/reply/generate` | Принудительная генерация проекта ответа по ID документа | JWT, роли op/admin |

Совместимость: обёртки над старыми `/api/letters/...` в Gateway (обратная совместимость до завершения внедрения).

### 2.2 ingest-service (внутренний REST/healt; события in/out)
- In: `documents.uploaded` (Kafka).
- Подкоманды (по HTTP-потребности): `GET /internal/ingest/{doc_id}/status`.
- Out: `document.parsed` (Kafka).

### 2.3 llm-service
- In: `document.parsed` (Kafka).
- Internal HTTP (для тестов бенчмарка KPI): `POST /internal/llm/classify`, `/ner`, `/summarize`.
- Out: `document.analyzed` (Kafka).

### 2.4 security-service
- In: `document.analyzed` (Kafka).
- Out: `security.assessed` (Kafka).
- Внешние вызовы: NVD API v2, bdu.fstec.ru (с ретраями/кэшем Redis), CMDB-коннектор.

### 2.5 reporting-service
- In: `security.assessed` (Kafka).
- Out: `report.ready`, `reply.generated` (Kafka).

### 2.6 Контракты внутренних вызовов (PostgreSQL — единый источник истины)
Таблицы перечислены в разделе 3. Сервисы читают/пишут БД в своей зоне ответственности:
- ingest: documents, attachments, extraction_metadata
- llm: threats, iocs, entities, summaries
- security: vulnerabilities, sla_events
- reporting: generated_responses, reports
- gateway: users, audit_log, templates (шаблоны — админ-зона, через gateway напрямую)

---

## 3. Модель данных (PostgreSQL)

Наследует и расширяет текущую модель монолита (13 таблиц). Новые поля выделены `[+]`.

### 3.1 users
`id, username[unique], password_hash, role(admin/user), full_name, is_active, created_at, updated_at`

### 3.2 documents (= letters)
`id(+)uuid, letter_number, letter_date, letter_type, status, subject, original_text, all_text,
parse_errors, created_by, created_at, updated_at,
source_filename[+], file_path[+], size[+], mime[+],
ocr_used[+], processing_stage[+] (uploaded|parsed|analyzed|assessed|reported|failed),
audit_user[+] (см. audit_log), sla[+] (normal|critical), routing[+] (default|infosec)`

### 3.3 attachments
`id(+), document_id, filename, file_path, file_type, parsed_text, parse_status, parse_errors, created_at`

### 3.4 threats
`id, document_id, number, group_name, threat_type, theme, archive_name, exe_name, malware_type, description, measures`

### 3.5 iocs
`id, document_id, ioc_type(ip|domain|email|hash|bdu|cve|software), value, context,
llm_validated[+] bool, source[+] (regex|llm), version[+] (для ПО: версия/релиз)`

### 3.6 entities  [+]
`id, document_id, entity_type(organization|deadline|contact), value, context`  (ТЗ 2.3.2 «стандартные»)

### 3.7 summaries  [+]
`id, document_id, summary(≤500 симв), confidence, created_at`  (ТЗ 2.3.3)

### 3.8 vulnerabilities
`id, document_id, bdu_id, cve_id, description, software, severity,
is_applicable, applicability_notes, action_type, action_details, response_point,
cvss_score[+], cpe[+], affected_range[+], fixed_version[+], patch_url[+],
cmdb_match[+] bool, current_version[+], target_version[+]`  (ТЗ 2.4)

### 3.9 sla_events  [+]
`id, document_id, sla(normal|critical), routing(default|infosec), reason, created_at`  (ТЗ 2.4)

### 3.10 threat_types (шаблоны типов угроз)
`id, name, key, description, created_at`

### 3.11 measure_templates
`id, name, threat_type_id, measures, full_text, is_default, created_at, updated_at`

### 3.12 vuln_types
`id, name, key, description, created_at`

### 3.13 vuln_measure_templates
`id, name, vuln_type_id, action_type, content, is_default, created_at, updated_at`

### 3.14 generated_responses
`id, document_id, content, edited_content, created_by, created_at, updated_at`

### 3.15 reports  [+]
`id, document_id, report_type(indicator_card|reply), file_path, filename(Report_...), generated_at`

### 3.16 audit_log  [+]  (ТЗ 4.3 «Аудит всех действий пользователей: кто, когда, какой файл»)
`id, user_id, username, action(upload|view|edit|generate|download|export|delete|login|logout|admin_*),
object_type(letter|attachment|user|template), object_id, filename[+], document_id[+],
ip_address[+], created_at` — хранение в Kafka `audit.events` (compact) + витрина в БД.

### 3.17 bootstrap_secrets (не показывается через API) — без изменений

### 3.18 login_attempts — без изменений (защита от bruteforce)

---

## 4. Правила консистентности
- Единый источник данных — PostgreSQL; Kafka — шина событий, не хранилище (кроме audit.compact).
- Обработка идемпотентна по `document_id`; повторные события не дублируют записи (upsert).
- Сбои: событие в DLQ + перевод документа в статус `failed`/`manual` + уведомление оператора.
- Тайм-ауты и ретраи внешних вызовов — см. `docs/phase1_design.md` (раздел «Надёжность»).