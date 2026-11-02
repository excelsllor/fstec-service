# ФСТЭК Сервис

Сервис автоматического формирования ответов на предписания ФСТЭК.
Микросервисная архитектура: gateway (:8666) + воркеры ingest/llm/security/reporting.

## Требования

- Python 3.10+
- Node.js 18+ (frontend)
- Kafka >= 3.x и Redis >= 7 (режим `kafka`; для локальной разработки достаточно SQLite-шины)

## Установка зависимостей

### Services (Python)
```bash
cd services
python -m venv .venv
.\.venv\Scripts\activate        # Windows
source .venv/bin/activate       # Linux
pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Запуск (dev режим)

### Windows
```bash
dev.bat
```

### Linux (РЕД ОС)
```bash
chmod +x dev.sh
./dev.sh
```

### Ручной запуск
```bash
cd services
powershell -File run_local.ps1    # Windows (gateway :8666 + 4 воркера, SQLite-шина)
bash run_local.sh                 # Linux
```

Затем (отдельный терминал):
```bash
cd frontend
npm run dev
```

Открыть: http://localhost:5173 (API: http://127.0.0.1:8666, docs /api/docs)

## Первый запуск

При первом входе система автоматически создаёт учётную запись администратора
(`admin`) со случайным паролем:

1. На экране входа появится карточка «Первичная инициализация» с логином и паролем
2. **Пароль показывается один раз** — запишите его (или нажмите «Скопировать»)
3. После первого входа пароль восстановить нельзя
4. Сразу после входа создайте дополнительные учётные записи в разделе «Пользователи»

## Использование

1. **Загрузить письмо** — выбрать PDF + вложения (DOC/DOCX/ODT/XLSX/RTF/TXT)
2. Система автоматически (конвейер через шину событий):
   - Извлечёт текст из всех файлов (OCR для сканов PDF при включении)
   - Определит тип письма (хакерская группировка / компрометация / уязвимости)
   - Найдёт угрозы и группировки
   - Извлечёт IOC (IP, домены, хэши, email, BDU, CVE)
   - Сопоставит уязвимости с NVD/BDU и рабочей CMDB
3. **Карточка письма** — 6 вкладок:
   - Информация — номер, дата, тип, вложения
   - Угрозы — список с группировками и мерами
   - IOC — IP, домены, хэши, email (с копированием)
   - Уязвимости — анализ применимости, действия
   - Ответ — генерация, редактирование, скачивание DOCX
   - Экспорт — 4 IOC-файла (emails.txt, ip_addresses.txt, domains.txt, ioc_indicators.txt)

## Tauri (desktop)

Десктоп-оболочка — веб-вью без встроенного бэкенда; требует запущенных
микросервисов (см. «Запуск (dev режим)»).

```bash
cd src-tauri
cargo tauri dev
```

## Тесты

```bash
cd services
python -m pytest tests -q
```

Смоук полного конвейера (нужен поднятый `run_local`):
```bash
python tools/services_smoke.py
python tools/services_smoke.py --all-formats   # docx/xlsx/odt/rtf/txt/pdf/doc
```

## Структура проекта

```
fstec-service/
├── services/           # микросервисы (Python/FastAPI)
│   ├── api_gateway/    # :8666 (auth, upload, документы, отчёты, reply)
│   ├── ingest_service/ # парсинг файлов + OCR
│   ├── llm_service/    # классификация (heuristic | vllm: Qwen3)
│   ├── security_service# NVD/BDU/CMDB, SLA, роутинг
│   ├── reporting_service # карточки индикаторов (DOCX), ответы
│   ├── shared/         # общие: config, db, bus (memory|sqlite|kafka), parsers, extractors
│   ├── tests/          # pytest-набор (E2E по форматам и конвейеру)
│   ├── tools/          # services_smoke.py, quality audit
│   ├── run_local.ps1 / run_local.sh
│   └── requirements.txt
├── frontend/           # React + TypeScript + MUI (API на :8666)
│   ├── src/
│   │   ├── api/        # API client
│   │   ├── store/      # Zustand (auth)
│   │   ├── components/ # Layout
│   │   └── pages/      # Login, Dashboard, Upload, LetterList, LetterDetail, Admin/Users
│   └── package.json
├── src-tauri/          # Tauri v2 (desktop shell, webview)
├── docs/               # архитектура, сборка под РЕД ОС, чек-лист
├── packaging/          # rpm/система (systemd-юниты микросервисов)
├── dev.bat             # Запуск (Windows)
├── dev.sh              # Запуск (Linux)
└── start.bat           # Запуск (Windows)
```

## Поддерживаемые форматы

| Формат | Движок |
|--------|--------|
| PDF (текст) | pdfplumber |
| PDF (скан) | OCR (tesseract/paddle, раздел настраивается) |
| DOCX | python-docx |
| DOC | olefile + CLX + UTF-16 scan |
| ODT | zipfile + XML |
| XLSX | openpyxl |
| RTF / TXT | striprtf / chardet |

## Конфигурация

Все переменные окружения — в `services/.env.example` (шина `memory|sqlite|kafka`,
OCR, LLM `heuristic|vllm`, security `mock|live`, CMDB, NVD/BDU).

## Бизнес-процесс

### Хакерская группировка
1. Загрузить письмо → система извлекает IOC и угрозы
2. Сгенерировать ответ (DOCX)
3. Экспортировать 4 IOC-файла
4. Оператор отправляет файлы по назначению

### Уязвимости
1. Загрузить письмо → система извлекает BDU/CVE
2. Для каждой уязвимости: отметить применимость
3. Выбрать действие: обновить ПО / компенсирующие меры / пропустить
4. Сгенерировать ответ (DOCX)