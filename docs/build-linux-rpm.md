# Linux rpm: микросервисный web-режим (РЕД ОС / ROSA / RHEL)

Приложение работает в браузере: микросервисы (gateway :8666 + воркеры
ingest/llm/security/reporting) запускаются **скрытыми системными сервисами**,
ярлык на рабочем столе открывает `http://127.0.0.1:8666`.

## Состав пакета

| Компонент | Что ставится |
|-----------|--------------|
| services/ | микросервисы (Python/FastAPI): `api_gateway`, `ingest_service`, `llm_service`, `security_service`, `reporting_service`, `shared` |
| frontend/dist | собранный Vite-бандл (обслуживается gateway) |
| systemd | `fstec-gateway.service` + `fstec-worker@.{ingest,llm,security,reporting}.service` |
| данные | `/var/lib/fstec-service` (БД, uploads, логи) |

Требования на целевой машине: **Python 3.10+** и Python-зависимости
(см. `services/requirements.txt`) — ставятся на этапе установки через pip.
Для офлайн-установки понадобится wheelhouse вашего дистрибутива.

## Сборка

Автоматизирована в `.github/workflows/build-linux-rpm.yml`:

| Job       | Где                   | Что делает                                            |
|-----------|-----------------------|-------------------------------------------------------|
| frontend  | ubuntu-latest         | `npm ci && npm run build` (Vite dist)                 |
| services-test | ubuntu-latest     | `pytest services/tests` (регрессия микросервисов)     |
| rpm       | rockylinux:9          | `rpmbuild -bb packaging/linux/fstec-service.spec`     |
| verify    | rockylinux:9          | установка rpm, запуск systemd, API-смоук на :8666     |

Артефакт: `fstec-service-rpm` → `fstec-service-0.1.0-1.el9.x86_64.rpm`.

Ручная сборка на Linux-машине:

```bash
# 1. Фронтенд
cd frontend
npm ci
npm run build

# 2. rpm (services + frontend/dist + systemd-юниты)
mkdir -p ~/rpmbuild/SOURCES
cp -a services ~/rpmbuild/SOURCES/services
cp -a frontend/dist ~/rpmbuild/SOURCES/frontend
cp packaging/linux/fstec-gateway.service packaging/linux/fstec-worker@.service \
   packaging/linux/fstec-service.desktop packaging/linux/fstec-service.png ~/rpmbuild/SOURCES/
rpmbuild -bb --define "_sourcedir $HOME/rpmbuild/SOURCES" \
  --define "_topdir $HOME/rpmbuild" packaging/linux/fstec-service.spec
# результат: ~/rpmbuild/RPMS/x86_64/fstec-service-*.rpm
```

## Установка

```bash
# с правами root:
rpm -ivh fstec-service-0.1.0-1.el9.x86_64.rpm
# или
dnf install ./fstec-service-0.1.0-1.el9.x86_64.rpm
# затем установить Python-зависимости (офлайн — из wheelhouse):
pip install -r /opt/fstec-service/services/requirements.txt
# systemd-юниты уже активны (см. %post)
```

После установки:
- юниты `fstec-gateway.service` и `fstec-worker@{ingest,llm,security,reporting}` включены и запущены;
- «ФСТЭК Сервис» — ярлык открывает `http://127.0.0.1:8666` в системном браузере;
- данные: `/var/lib/fstec-service` (БД, uploads, логи);
- логи: `journalctl -u fstec-gateway`, `journalctl -u fstec-worker@llm` и т.п.

Проверка: `curl http://127.0.0.1:8666/api/auth/status` → `{"needs_setup":true}`.

Первый вход: сервис сам создаёт администратора и показывает одноразовый пароль
на экране инициализации (логин `admin`). После входа пароль меняется.

## Управление сервисами

```bash
systemctl status fstec-gateway fstec-worker@{ingest,llm,security,reporting}
systemctl restart fstec-gateway
systemctl disable fstec-worker@{ingest,llm,security,reporting}
```

## Удаление

```bash
rpm -e fstec-service
# сервисы остановятся; данные в /var/lib/fstec-service сохраняются
```

## Настройка

- Адрес: `127.0.0.1:8666` (только localhost), документирование API: `/api/docs`.
- Конфигурация — переменные окружения в `/usr/lib/systemd/system/fstec-gateway.service`
  и `fstec-worker@.service` (режим шины, OCR, LLM, security, CMDB; см. `services/.env.example`).
- Режим шины по умолчанию для rpm: `FSTEC_EVENT_BUS=sqlite` (без Kafka/Redis);
  для выпуска — Kafka (`fstec-kafka`/`fstec-redis`).

## Ограничения

- Интерфейс — в браузере (нет отдельного окна).
- Проверка GUI на реальной РЕД ОС (7 и 8) — вручную: установить rpm, открыть ярлык,
  пройти инициализацию и полный цикл (загрузка письма → генерация → скачивание DOCX):
  `python tools/services_smoke.py --all-formats`.
- CI-верификация гоняет API-смоук на rocky:9.