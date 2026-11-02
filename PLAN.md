# План разработки: Сервис обработки писем ФСТЭК (ЛГТУ)

Основание: `TEKhNIChESKOE_ZADANIE_po_proektu_LGTU.docx` — полное соответствие ТЗ.

## Зафиксированные проектные решения
- **Полное соответствие ТЗ** (каждый пункт выполняется).
- **Архитектура:** реальные микросервисы + **Kafka** (ТЗ 3.1).
- **LLM:** реальная локальная модель **Qwen3-14B-Q4** на **RTX 4090 24 ГБ**, vLLM, абстрактный LLMProvider, чанкинг ≤4k + continuous batching + regex-first (для KPI 5с/500+).
- **Security:** реальная интеграция **BDU (bdu.fstec.ru) + NVD API v2**; **CMDB Заказчика** — настраиваемый REST/коннектор с моком в dev.
- **Очередь:** Kafka (топики между сервисами).
- **Железо:** RED OS 8.x · CPU 16–24 ядра · RAM 64 ГБ · RTX 4090 24 ГБ · SSD 512 ГБ (система+БД+веса) + HDD 2 ТБ RAID1 (документы/архив). bcache не нужен (page cache покрывает hot-данные).

## Сверка ТЗ → статус

| Пункт ТЗ | Статус | Работа |
|---|---|---|
| 2.1 Инжест (drag-drop, PDF/DOC/DOCX/RTF, 20МБ, ≤10 файлов) | частично | лимиты, пакет 10, drag-drop, `/upload` |
| 2.2 Текст/OCR (pdfplumber + **Tesseract**) | парсеры есть, **OCR НЕТ** | Tesseract (ru) в ingest-сервис |
| 2.3.1 Классификация через LLM | rule-based | Qwen3-14B классификация |
| 2.3.2 NER (орг/сроки/контакты; IPv4/**IPv6/CIDR**; FQDN; email+cplus; BDU/NVD/CVE; ПО+версии) | IPv4/домен/email/CVE/BDU есть | IPv6/CIDR, орг/сроки/контакты, regex+LLM-валидация |
| 2.3.3 Саммари ≤500 симв | нет | через Qwen3-14B |
| 2.4 Security Posture Analyzer (NVD/BDU → CMDB → matching → SLA → рекомендация) | **НЕТ** | новый security-сервис |
| 2.5.1 Карточка индикаторов (`Report_[имя]_[дата].docx`, шапка + 4 раздела + таблица уязв.) | другой формат | переработать |
| 2.5.2 Проект ответа (угроза/нет) | есть | адаптировать под security-анализ |
| 2.6 REST API (`/upload`, `/documents`, `/reports/.../download(_raw)`, `/reply/generate`) | другая схема | добавить совместимые endpoint'ы |
| 3.1 Микросервисы + Kafka (gateway, файлы, LLM, безопасность, генерация) | монолит | разбить |
| 4.1 Производительность (≤2с/≤5с/≤3с/500+ в час) | частично | чанкинг/батч/воркеры + бенчмарк |
| 4.2 Надёжность (99.5%, RTO≤30мин, ретраи ≤3, ручной режим) | частично | формализовать |
| 4.3 Безопасность (TLS1.3, шифр., аудит кто/когда/файл) | есть | расширить аудит |
| 4.4 Юзабилити (drag-drop, подсветка, К/Ж/З риски, корректировка) | подсветка+корректировка есть | drag-drop, **К/Ж/З** |
| 6 Документация (7 документов) | чек-лист есть | полный пакет |
| 7.1 Приёмка (OCR скана, грязные тексты, **крит. кейс BDU:2026→bdu.fstec.ru→CMDB→DOCX красная подсветка→ответ**) | частично | автотесты-кейсы |

## Фазы (сопоставлены этапам ТЗ §5)

### Фаза 0 — Каркас монолита ✅ (уже сделано в прошлой жизни проекта)
- Tauri v2 + React + FastAPI + SQLite + JWT auth, парсеры, генератор, web-UI.
- Сборки Windows NSIS/MSI, CI на Linux rpm и Windows.

### Фаза 1 — ПРОЕКТИРОВАНИЕ (ТЗ этап 1, ~2 нед) — ✅ завершена (6 артефактов)
- [x] Архитектурный документ AS-IS / TO-BE (монолит → микросервисы) — `docs/architecture_as_is_to_be.md`
- [x] Схемы Kafka-топиков, интерфейсы сервисов, модель данных — `docs/phase1_design.md`
- [x] JSON-схемы обмена NVD/BDU/CMDB (приложение 8) — `docs/phase1_json_schemas.md`
- [x] Структура DOCX-отчётов (2.5.1) и категорий документов — `docs/phase1_reporting.md`
- [x] Приложения 8 (категории, CMDB-схема, требования к АО, JSON-схемы) — `docs/phase1_hardware.md` + `docs/phase1_appendix8.md`

### Фаза 2 — MVP ЯДРО (ТЗ этап 2, ~8 нед) — ✅ ЗАВЕРШЕНА (каркас + фронтенд)
- [x] Каркас микросервисов + docker-compose + Kafka + Redis — `services/` (shared-библиотека, 5 сервисов, `docker-compose.yml`); Kafka/Redis/PG в dev отключаемы через `FSTEC_EVENT_BUS=memory`
- [x] ingest-сервис: лимиты 20МБ/10 (ТЗ 2.1), форматы (PDF/DOC/DOCX/ODT/XLSX/RTF), Tesseract OCR (rus) — `services/ingest_service/`
- [x] llm-сервис: Qwen3-14B-Q4 (vLLM) + heuristic (dev), классификация, NER (IPv6/CIDR, орг/сроки/контакты), саммари ≤500, regex-first — `services/llm_service/`
- [x] API Gateway: `/upload`, `/documents[/{id}]`, `/reports/{id}/download(_raw)`, `/reply/generate` + совместимость со старыми `/api/letters/...` — `services/api_gateway/`
- [x] reporting-сервис: карточка индикаторов 2.5.1 + проект ответа 2.5.2 — `services/reporting_service/`
- [x] security-сервис (мок-CMDB по структуре Приложения 8; реальные BDU/NVD — Фаза 3) — `services/security_service/`
- [x] Фронтенд: endpoint'ы ТЗ 2.6, drag-drop, фильтры/пагинация, К/Ж/З риски, редактор ответа, экспорт/скачивание (порт 8666)
  - `frontend/src/api/client.ts` → `/upload` (files[]), `/documents[/{id}]`, `/reports/{id}/download(_raw)`, `/reply/generate`, `VITE_API_BASE` default `http://127.0.0.1:8666`
  - `frontend/src/pages/Upload.tsx` — drag&drop, пакет до 10 файлов
  - `frontend/src/pages/LetterDetail.tsx` — К/Ж/З-чипы рисков (ТЗ 4.4), кнопки «Карточка индикаторов»/«Исходник»
  - `frontend/src/pages/LetterList.tsx` — серверные фильтры `letter_type`/`status` + пагинация
- [x] Gateway доработан под полный UI: `/documents/{id}` с полными массивами (attachments/threats/iocs/vulnerabilities/entities/summary), preview ответа, обновление мер/уязвимостей, экспорт IOC (txt/docx), `_content_disposition` для кириллицы
- [x] Новые модули: `services/shared/generator/reply_preview.py` (секции редактора), `ioc_export.py` / `ioc_export_docx.py`
- [x] Тесты: 35 passed, 1 skipped (в т.ч. новые: полный detail, preview/response, экспорт IOC)

### Фаза 2.5 — OCR (PaddleOCR GPU) + LLM (Qwen3 + RuBERT) — ДОПОЛНЕНИЕ (утверждено)
Логика: PaddleOCR на GPU (CUDA, RTX 4090) для качества/скорости русского скана;
Qwen3-14B (vLLM) остаётся для саммари/NER-верификации/ответов, а быструю
классификацию (KPI) берёт RuBERT. Размещение: GPU целиком под vLLM, RuBERT — CPU.

**OCR — PaddleOCR (ТЗ 2.2):**
- [x] `services/shared/parsers/ocr.py` → абстракция провайдеров: `PaddleOCREngine` (GPU/CUDA) и `TesseractOCR` (CPU, fallback); общий `ocr_pdf_bytes(content) -> (text, errors)`
- [x] `shared/config.py`: `FSTEC_OCR_ENGINE=auto|paddle|tesseract` (default `auto`: paddle → tesseract), `FSTEC_OCR_DEVICE=gpu|cpu` (в dev `cpu`, в проде `gpu`)
- [x] Зависимости: `paddlepaddle-gpu` + `paddleocr` — отдельный блок в `requirements.txt` (не тянуть в dev без GPU)
- [x] PDF → изображения: `pdf2image`/`poppler`; распознавание `lang="ru"` (det+rec+cls)
- [x] `docker-compose.yml`: ingest-сервис → `deploy.resources.reservations.devices` (GPU), env `FSTEC_OCR_ENGINE=paddle`
- [x] Исправление бага: `ingest_service/worker.py` вызывал `ocr_pdf_bytes()` как строку, а функция возвращает `(text, errors)` — починено, OCR-ошибки в `parse_errors`
- [x] Тесты: юнит выбора провайдера + fallback, мок-Paddle — `tests/test_ocr.py`

**LLM — Qwen3 + RuBERT (ТЗ 2.3):**
- [x] `services/llm_service/rubert.py`: `RuBERTClassifier` на `DeepPavlov/rubert-base-cased-conversational`; ленивая загрузка (singleton), `FSTEC_RUBERT_DEVICE=cpu|gpu`, дефолт `cpu`
- [x] Классификация: embedding `[CLS]` + cosine-к-NN по фразам-сеедам категорий → `(label, confidence)`; низкая уверенность → heuristic-fallback
- [x] Qwen3 (vLLM) остаётся за: саммари ≤500 симв, верификация NER-сущностей, генерация проекта ответа (2.5.2), пересборка спорных кейсов; дообучение RuBERT — Фаза 3
- [x] `provider.py`/`analyze.py`: цепочка `RuBERT → heuristic (низкая уверенность) → Qwen-валидация (if FSTEC_LLM_PROVIDER=vllm)`
- [x] Зависимости: `torch`/`transformers` — опциональный блок, импорты защищены (дев работает без весов)
- [x] Тесты: классификатор на мок-центроидах + fallback; CI-тест с реальной моделью — skip без весов — `tests/test_rubert.py`
- [x] Документация: `docs/phase1_hardware.md` §1.1, `docs/phase1_design.md` §1.4; `.env.example`, `docker-compose.yml`

**Фронтенд (остаток Фазы 2, ТЗ 4.4):**
- [x] Переезд на endpoint'ы ТЗ 2.6, drag-drop, подсветка К/Ж/З, корректировка ответа

**Фронтенд (остаток Фазы 2, ТЗ 4.4):**
- [x] Переезд на endpoint'ы ТЗ 2.6, drag-drop, подсветка К/Ж/З, корректировка ответа

### Фаза 3 — МОДУЛЬ БЕЗОПАСНОСТИ (ТЗ этап 3, ~6 нед)
- [x] security-сервис: клиенты bdu.fstec.ru + NVD API v2 (CVSS, CPE, диапазоны, патч) — `services/security_service/{nvd_client,bdu_client,enriched}.py`
- [x] CMDB-коннектор (REST, auth none/bearer/basic, пагинация; мок в dev) — `services/security_service/{cmdb,cmdb_mock}.py`
- [x] Версионный matching → Match — `services/security_service/versioning.py` + `assessment._match_cmdb`
- [x] Keep-all: все уязвимости в карточке; `cmdb_match` как флаг, К/Ж/З = match ∨ severity
- [x] SLA=Критический, маршрутизация InfoSec, заметка «Обновить {P} с {a} до {b}» (fallback-шаблон)
- [x] Ретраи ≤3 с экспоненциальной задержкой + кэш (Redis→memory) + graceful-fallback (raw, DLQ `documents.failed`)
- [x] fixed_version: поле BDU → regex «до версии X» → пусто
- [x] REST-бэкенд: `PUT /documents/{id}/vulnerabilities/{v}`, поле `source` в сериализации (ТЗ 2.6)
- [x] Тесты: `tests/{fakes,test_versioning,test_nvd_client,test_bdu_client,test_cmdb_connector,test_assessment,test_security_live}.py` — итого **63 passed, 1 skipped**
- [x] Красная подсветка в UI по результатам анализа: К/Ж/З = `cmdb_match ∨ severity`; карточка показывает источник, текущую/целевую версию и рекомендацию (`LetterDetail.tsx`)
- [x] Локальный мульти-процессный запуск без Kafka: `shared/bus.py` → `SqliteEventBus` (`bus_message`/`bus_cursor`), `run_local.ps1`/`.sh`, HTTP-смоук `tools/services_smoke.py` (E2E upload → completed → отчёт → ответ); SQLite WAL/busy_timeout в `shared/db.py`; extractor видит фразу «до версии X» из следующего предложения → `fixed_version`
  - Проверено локально: **PASS** (doc → parsed → analyzed → assessed → completed; Log4j source=manual, cmdb_match=True, target=2.17.0; карточка DOCX; ответ 355 символов)

### Фаза 4 — ТЕСТИРОВАНИЕ И ПИЛОТ (ТЗ этап 4, ~4 нед)
- [ ] Автотесты приёмки: OCR скана, грязные тексты, критический кейс BDU:2026
- [ ] KPI-бенчмарк (≤2с/≤5с/≤3с/500+/час, Precision/Recall ≥99%, ≥75% авто)
- [ ] Пилот на реальных документах (≥1000 шт. по ТЗ)
- [ ] Нагрузочное тестирование

### Фаза 5 — ВНЕДРЕНИЕ И ОБУЧЕНИЕ (ТЗ этап 5, ~2 нед)
- [ ] Развёртывание в productive контуре (RED OS, CUDA 12, vLLM)
- [ ] Руководства + инструкция CMDB
- [ ] Обучение операторов/админов

### Фаза 6 — ДОКУМЕНТАЦИЯ + ПРИЁМКА
- [ ] Пакет 7 документов (§6): AS-IS/TO-BE, OpenAPI, рук. админа, рук. пользователя, CMDB-инструкция, отчёт об отсутствии уязв., протоколы приёмки
- [ ] Протоколы тестирования + критерии приёмки (§7.1)

### Фаза 7 — СОПРОВОЖДЕНИЕ (ТЗ этап 6, 3 мес)
- [ ] Гарантийная поддержка, исправление, донастройка LLM-промптов (опц. LoRA)

## Ключевые риски
1. **KPI 5с/500+ (14B-Q4, одна 4090)** — чанкинг ≤4k + батч + regex-first; валидация в Фазе 4. Резерв: 2× A10/4090.
2. **Реальные BDU/NVD живут по сети** — ретраи + ручной режим по ТЗ.
3. **27B на 4090 не помещается/не тянет KPI** — отложен; целевая 14B-Q4.
4. **CMDB Заказчика нет в dev** — мок-коннектор, реальный конфиг на внедрении.