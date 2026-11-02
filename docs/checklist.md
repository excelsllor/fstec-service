# Чек-лист перед выпуском

Все пункты должны быть зелёными перед поставкой новой версии.

## Сборка и тесты

- [ ] `python -m pytest services/tests -q` — без ошибок (E2E по форматам, конвейер, лимиты, конкурентность)
- [ ] Живой смоук: `dev.bat` (или `run_local`), затем `python services/tools/services_smoke.py`
      и `python services/tools/services_smoke.py --all-formats` — документы завершаются `completed`, отчёт+ответ генерируются
- [ ] `npm run build` во `frontend/` — без ошибок
- [ ] (опц.) `npx tauri build --bundles msi,nsis` — десктоп-оболочка собирается (без sidecar-бэкенда)

## Функциональность (важные сценарии)

- [ ] upload → `uploaded → parsed → analyzed → assessed → completed`
- [ ] Форматы: PDF (текст), PDF (скан, OCR), DOCX, DOC, XLSX, ODT, RTF, TXT
- [ ] Лимиты загрузки: файл > 20 МБ → 413; пакет > 10 файлов → 413; пустой пакет → 400
- [ ] Magic-bytes: поддельное расширение (MZ в .docx и т.п.) → 415
- [ ] NVD/BDU/CMDB live-режим (на сервере с сетью): уязвимость сопоставлена, SLA/роутинг верные
- [ ] LLM live: `FSTEC_LLM_PROVIDER=vllm` (Qwen3) — классификация/NER/саммари реальными ответами
- [ ] Kafka-режим: полный конвейер поверх Kafka на тестовом кейсе повторяется хотя бы 2 раза подряд
- [ ] KPI на целевой конфигурации: OCR ≤ 2 с, обработка письма ≤ 5 с, генерация отчёта ≤ 3 с, пропускная способность 500+ писем/час

## Качество (ТЗ 4.1)

Локальная валидация на корпусе 12 реальных писем ФСТЭК: `python services/tools/quality_eval.py`
(провайдер `vllm` = llama.cpp/Qwen3-14B, `-c 16384`, CHUNK 15400, энкодер USER2-base) →
отчёт `services/data/quality/quality_report.json` (финальный прогон).

- [x] Авто-классификация ≥ 75%: **100%** (11 hacker + 1 compromise, совпадение с эталоном)
- [x] Саммари ≤ 500 знаков: **12/12**
- [x] IP IoC: precision **0.996** / recall **1.0** (1 FP — дата `06.04.26.7`)
- [x] Домены (полный список письма, приложения + списки тела): precision **0.991** / recall **0.997**
      (остаточные расхождения — эталонные артефакты или реальные TP: `r99.fssp.gov@outlook.com`, `trueconf.ru`)
- [x] Регрессия: `pytest services/tests -q` — 97 passed

### Постадийная верификация 2026-09-09 (артефакты `services/data/quality/check_stage*.json`)

- [x] **Категория отдельно**: regex 12/12; USER2-base 11/12 (91.7%, miss 9-77 — закрывается regex `compromise`);
      vLLM standalone 2/3 (9-99 — таймаут полного контекста, в конвейере LLM лишь валидирует regex)
- [x] **Угрозы**: 122 threat-секции на 11 hacker-письмах, group/theme/архив/exe/меры извлекаются;
      кросс-проверка с «Проект мер №_18_XX.docx» — 7/7 (тема, группировка, keywords мер)
- [x] **NER (2.3.2)**: исправлено (organizations без мусора, новый парсер срока «до DD месяц ГГГГ»,
      email-контакты); дедлайны на всех 12 письмах (24.06.2026 → `до 24.06.2026`)
- [x] **Уязвимости**: 0 ложных против hacker-писем (BDU-упоминания в теле — реальное обогащение);
      BDU live **работает** (bdu.fstec.ru, TLS-fallback `verify=False` на SSL_CERT_FAIL,
      BDU:2021-05969 → Log4j JNDI, CVSS 10, fix 2.17.0); NVD live — CVE-2024-3094
- [x] **SLA/routing**: 9-99/9-113 (Microsoft Office в CMDB) → `critical/infosec`; синтетика live → `critical/infosec`
- [x] **Карточка + ответ (2.5.1/2.5.2)**: исправлено ветвление (уязвимости hacker-писем больше не
      подменяют меры антифишинга); артефакты валидны, сверка с эталоном «Ответ на письмо 9-XX.docx»
- [x] **Форматы (2.2)**: 7/7 (docx/xlsx/odt/rtf/txt/pdf/doc), IoC-маркеры извлекаются; OCR — серверный пункт
      (paddleocr/pdf2image не установлены локально)
- [x] **OCR локально (PaddleOCR)**: стек paddlepaddle 2.6.2 + paddleocr 2.7.3 + PyMuPDF-рендер
      (paddle 3.x/PIR ломается — зафиксировано); 3 PDF → 0 ошибок, выравнивание текста ~65-75%
- [x] **E2E-генерация (полная цепочка)**: upload→parse→analyze (LLM Qwen3-14B@16384)→assess
      (BDU/NVD live)→card+reply по всем 12 письмам — все `completed` (д. `check_e2e.json`);
      ответы перегенерированы текущим генератором: 6-17 блоков на письмо, реквизиты 12/12,
      меры эталона 146/157 (93%), avg ratio 0.81 (было 0.14-0.29); 9-77 (compromise) — ветка
      «контроль журналов + внеплановое сканирование» вместо NO_RISK; тема чистится от Fwd/Re
- [x] **Шаблонный проект ответа + библиотека мер (LLM-подбор)**: таблицы `measures`,
      `measure_candidates`, `reply_templates`, `intro_fragments` (сид из
      `data/generator/*.json` — 11 мер, 14 интро-фрагментов, 4 шаблона); LLM одним вызовом
      возвращает `{block: {fragment_id, measure_ids[], new_measures[]}}`, fallback — прежний
      детерминированный генератор; план сохраняется в `GeneratedResponse.plan_json`;
      новые меры помечаются в предпросмотре (`source: new`) и уходят администратору
      (`/admin/measures/candidates` → accept/reject, accept добавляет в библиотеку);
      ручные правки мер письма (`explicit_measures`) перекрывают машинный подбор;
      регрессия pytest **108 passed**; сверка с эталоном: покрытие мер библиотекой
      **619/623 (99%)** (4 «пробела» — приписки «Дополнительно сообщаем…», не меры),
      отчёт `data/quality/measures_library_coverage.json`

## Безопасность

- [ ] На чистой БД: `GET /api/auth/status` → `needs_setup: true`
- [ ] Bootstrap-пароль администратора доступен один раз (экран инициализации), bcrypt-хэш в БД
- [ ] После первого успешного входа: `needs_setup: false`
- [ ] Подделанный JWT (старый/чужой ключ) → 401
- [ ] Rate-limit логина: 5 неудач за 5 минут → 429
- [ ] Загрузка недопустимого расширения → 415, превышение лимитов → 413
- [ ] Magic bytes при загрузке файлов (проверка сигнатуры по расширению)
- [ ] Object-level auth: удаление/изменение чужого письма → 403 (non-admin)
- [ ] `/docs`/`/redoc`/`/openapi.json` скрыты по умолчанию (`FSTEC_DISABLE_DOCS=1`)
- [ ] Сервисы запускаются от fstec (не root), `/var/lib/fstec-service` 0700
- [ ] В репозитории нет секретов

## Данные

- [ ] Продакшн-данные: `DATA_DIR` (в `services/.env`: каталог data), БД + uploads
- [ ] Резервная копия БД перед обновлением

## Код

- [ ] `npm run lint` — 0 ошибок
- [ ] `services/requirements.txt` синхронизирован с установленными версиями
- [ ] `services/.env.example` отражает все переменные конфигурации