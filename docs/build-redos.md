# Сборка под РЕД ОС (Linux)

> **Рекомендуется:** универсальный web-режим (один rpm для РЕД ОС 7/8, без
> WebKitGTK/Tauri) — см. `docs/build-linux-rpm.md`. Ниже — dev-режим и
> Tauri-оболочка (только для дистрибутивов с `webkit2gtk4.1`, РЕД ОС 7 не
> подходит).

Релиз для РЕД ОС собирается на машине с РЕД ОС (x86_64). Скрипт `dev.sh` и
инструкция ниже покрывают dev-режим; сборка пакета (.rpm) описана в
`docs/build-linux-rpm.md`.

## Предварительные требования

```bash
sudo dnf install -y \
  python3 python3-pip python3-devel \
  nodejs npm \
  cargo rustc \
  gcc-c++ \
  libwebkit2gtk4.1-devel openssl-devel \
  librsvg2-devel \
  rpm-build
```

## Services (микросервисы)

```bash
cd services
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
# запуск dev-стека: bash run_local.sh (поднимает gateway :8666 + 4 воркера)
```

## Frontend

```bash
cd frontend
npm install
npm run build
```

## Desktop (Tauri, webview без бэкенда)

```bash
cd src-tauri
npx tauri build --bundles rpm,deb
# результат: target/release/bundle/rpm/*.rpm, target/release/bundle/deb/*.deb
```

Для запуска без установки: `npx tauri dev` (требует запущенных микросервисов
через `services/run_local.sh` + frontend dev-server).

## Особенности

- Десктоп — веб-оболочка без sidecar: API ожидается на `http://127.0.0.1:8666`
  (gateway микросервисов).
- Данные: по умолчанию `services/data` (env `FSTEC_DATA_DIR` переопределяет).
- Gateway слушает только `127.0.0.1:8666` — наружу не публикуется; docs: `/api/docs`.
- Проверка после установки: запустить сервисы, `curl http://127.0.0.1:8666/api/auth/status`
  → `{"needs_setup":true}`.
- Смоук полного конвейера: `python services/tools/services_smoke.py --all-formats`.

## Ограничения

- Парсеры и генерация не зависят от Windows; но сборка .msi/.nsis возможна
  только на Windows (WebView2 + WiX/NSIS).
- Локальные микросервисы по умолчанию работают на SQLite-шине (без Kafka/Redis);
  производственный режим — Kafka/Redis/PostgreSQL по `services/.env.example`.