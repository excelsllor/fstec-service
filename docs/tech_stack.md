# Технологический стек

Сервис обработки писем ФСТЭК (ЛГТУ). Ниже — фактический стек по репозиторию
(`services/requirements.txt`, `frontend/package.json`, `services/docker-compose.yml`,
`services/Dockerfile`, `packaging/`).

## 1. Топология (prod, docker-compose)

```
клиенты (локалка)
      │  :80
   [ nginx ]  ── SPA (React) + прокси /gw → api-gateway:8666
      │
 [ api-gateway :8666 ]
      │  Kafka
 [ ingest ] [ llm ] [ security ] [ reporting ]
      │         │            │
 [ Postgres ] [ vLLM ]  [ BDU / NVD / CMDB заказчика ]
 [ Redis ]
```

- Клиенты стучатся по локалке на nginx (`:80`); nginx отдаёт SPA и проксирует API
  (`location /gw/` → `api-gateway:8666/`).
- Сервер имеет интернет для внешних БД (BDU ФСТЭК, NVD) и доступ к CMDB заказчика.

## 2. Backend

| Компонент | Технология | Версия |
|---|---|---|
| Язык | Python | 3.10+ (dev), 3.12 (образ) |
| Web-фреймворк | FastAPI | 0.140.7 |
| ASGI-сервер | Uvicorn[standard] | 0.51.0 |
| ORM | SQLAlchemy | 2.0.51 |
| Валидация | Pydantic | 2.13.4 |
| Auth | python-jose[cryptography], bcrypt | 3.5.0 / 5.0.0 |
| Multipart | python-multipart | 0.0.32 |
| Шина событий (prod) | aiokafka (Kafka) | 0.11.0 |
| Шина (dev) | SQLite/memory (`SqliteEventBus`) | — |
| Кэш | redis | 5.2.1 |
| HTTP-клиент | httpx | 0.28.1 |
| Драйвер БД | psycopg2-binary | 2.9.10 |
| Диагностика | psutil | 5.9.8 |

## 3. Обработка документов и OCR

| Задача | Технология | Версия |
|---|---|---|
| PDF-текст | pdfplumber | 0.11.10 |
| DOCX | python-docx | 1.2.0 |
| XLSX | openpyxl | 3.1.5 |
| DOC (OLE) | olefile | 0.47 |
| RTF | striprtf | 0.0.26 |
| Кодировки | chardet | 7.4.3 |
| Изображения | Pillow | 12.2.0 |
| PDF → изображения | poppler-utils | (системный) |
| OCR (основной) | PaddleOCR (GPU/CUDA cu118) | paddleocr 2.7.3, paddlepaddle-gpu 2.6.2 |
| OCR (fallback) | Tesseract (rus+eng) | (системный) |

PaddleOCR ставится только в образ ingest-service (`requirements-ocr.txt`,
build arg `WITH_OCR=true`), т.к. тянет CUDA-колёса.

## 4. LLM / NLP

| Задача | Технология |
|---|---|
| Генерация/саммари/классификация | vLLM (OpenAI-совместимый API) + **Qwen/Qwen3.5-9B** |
| Быстрая классификация | RuBERT `DeepPavlov/rubert-base-cased-conversational` (CPU) |
| Fallback без GPU | heuristic-провайдер |
| Генерация ответов | regex-first + шаблоны/меры + LLM-план (`templated_reply.py`) |
| NER | regex (IPv4/IPv6/CIDR, FQDN, email, CVE/BDU) + LLM-верификация |

- Инференс: сервис `vllm` (образ `vllm/vllm-openai`), модель скачивается при первом старте.
- GPU: RTX 4090 24 ГБ; `VLLM_GPU_MEMORY_UTILIZATION=0.80` (запас под PaddleOCR).

## 5. Интеграции безопасности

| Источник | Протокол/API |
|---|---|
| BDU ФСТЭК | `https://bdu.fstec.ru` (HTML `/vul/...`) |
| NVD | API v2 `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| CMDB заказчика | REST (auth none/bearer/basic, пагинация); мок в dev |

Защита: проверка TLS (fallback `verify=False` только dev), защита от XXE,
rate-limit логина, аудит (кто/когда/файл), JWT.

## 6. Данные и инфраструктура

| Компонент | Технология | Версия |
|---|---|---|
| БД (prod) | PostgreSQL | 16-alpine |
| Кэш | Redis | 7-alpine |
| Брокер | Apache Kafka (KRaft, bitnami) | 3.7 |
| Оркестрация | Docker Compose | — |
| Reverse proxy / UI | nginx | 1.27-alpine |
| Базовый образ backend | python | 3.12-slim |
| Базовый образ frontend | node | 22-slim |
| БД (dev) | SQLite (WAL) | — |

## 7. Frontend

| Компонент | Технология | Версия |
|---|---|---|
| UI-библиотека | React | 19.2.7 |
| Язык | TypeScript | ~6.0.2 |
| Сборка | Vite | 8.1.1 |
| Компоненты | MUI (@mui/material, @mui/icons-material) | 9.2.0 |
| Роутинг | react-router-dom | 7.18.1 |
| Состояние | Zustand | 5.0.14 |
| HTTP | axios | 1.18.1 |
| Линтер | oxlint | 1.71.0 |

- API-база задаётся `VITE_API_BASE`; в образе nginx — `/gw` (прокси на gateway).

## 8. Desktop и упаковка

| Артефакт | Технология |
|---|---|
| Desktop | Tauri v2 (@tauri-apps/cli 2.11) |
| Windows | NSIS / MSI |
| Linux | RPM (`packaging/linux/fstec-service.spec`) + systemd |
| CI | GitHub Actions (`build-linux-rpm.yml`, `build-windows.yml`) |

systemd-юниты: `fstec-gateway.service`, `fstec-worker@{ingest,llm,security,reporting}.service`.

## 9. Порты (prod)

| Порт | Сервис | Доступ |
|---|---|---|
| 80 | nginx (UI + `/gw` → gateway) | локалка (клиенты) |
| 8666 | api-gateway | `127.0.0.1` (внутрь через nginx) |
| 8000 | vLLM | `127.0.0.1` |
| 5432 | PostgreSQL | `127.0.0.1` |
| 6379 | Redis | `127.0.0.1` |
| 9092 | Kafka | `127.0.0.1` |

## 10. Целевое железо (ТЗ)

RED OS 8.x · CPU 16–24 ядра · RAM 64 ГБ · NVIDIA RTX 4090 24 ГБ ·
SSD 512 ГБ (система+БД+веса) + HDD 2 ТБ RAID1 (документы/архив) ·
CUDA 12 / драйвер NVIDIA + NVIDIA Container Toolkit.
