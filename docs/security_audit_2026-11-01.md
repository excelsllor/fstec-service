# Security audit — 2026-11-01

## Итог

Стенд можно показывать завтра в режиме пилотной демонстрации через браузер. Для production-приёмки требуется отдельная работа с base image и сетевым периметром.

Критическая уязвимость `python-jose` устранена заменой на PyJWT. Критические уязвимости Node.js в production-runtime отсутствуют, потому что Node.js в runtime не используется: frontend — статическая сборка, которую отдаёт Nginx. Node.js нужен только на этапе сборки.

## Версии

| Компонент | Версия |
|---|---|
| Node.js на ПК разработчика | 24.16.0 |
| npm | 11.13.0 |
| Node.js в Docker build | закреплён `node:22.23.4-slim` |
| Python в API/security/reporting | 3.12.15 |
| PyJWT | 2.15.1 |
| FastAPI | 0.140.7 |
| Nginx | 1.29-alpine |
| PostgreSQL | 16-alpine |
| Redis | 7-alpine |

## Node.js

Node.js v24.16.0 на ПК разработчика старше security-релиза от 21.10.2026 и затронут исправленными там проблемами, в том числе:

- CVE-2026-105482 — DNS NUL truncation, high;
- CVE-2026-105483 — TLS hostname bypass, high;
- CVE-2026-106069 — TLS hostname bypass, high;
- CVE-2026-111497 — Brotli out-of-bounds write / RCE, high.

Исправленные версии: 22.23.4, 24.22.1, 26.12.1. Docker build переведён на `node:22.23.4-slim`. Локальный Node.js следует обновить до 24.22.1 перед следующей сборкой вне Docker.

Важно: в production-контейнере Node.js отсутствует. Уязвимости Node.js влияют только на build-среду, а не на runtime стенда.

## Frontend-зависимости

После обновлений:

- production vulnerabilities: 0;
- all dependencies vulnerabilities: 0;
- `follow-redirects` 1.16.2;
- `vite` 8.3.5.

До исправления были high-уязвимости `follow-redirects` и dev-зависимости Vite; они устранены.

## Python/backend

Найдена критическая уязвимость:

- CVE-2026-85394 / PYSEC-2026-4298 — python-jose algorithm confusion, Critical 9.3.

Также была high-уязвимость `ecdsa` CVE-2024-23342, приходившая транзитивно с python-jose.

Действия:

- `python-jose` удалён;
- JWT переведён на `PyJWT==2.15.1`;
- ecdsa больше не входит в зависимости;
- JWT decode по-прежнему использует явный allowlist `algorithms=["HS256"]`;
- `pip-audit` по приложению: 0 известных уязвимостей после обновления.

## Trivy

Сканирование `services-api-gateway:latest`:

- 1 critical и 91 high в OS-пакетах;
- critical: CVE-2026-6653 `libxml2` 2.9.14, upstream fixed 2.11.0; Debian fixed version в текущем образе отсутствует;
- Python-зависимостей с critical/high после замены PyJWT не осталось.

Сканирование `services-nginx:latest`:

- 2 high: CVE-2026-92392 `curl`/`libcurl` 8.22.0-r0, fixed 8.23.0-r0.

Mitigation:

- не подавать на стенд недоверенные XML/DOCX/PDF во время демонстрации;
- обновить base images после появления Debian/Alpine fixed packages;
- пересобрать Nginx после обновления Alpine-пакета curl;
- перед production-приёмкой повторить Trivy и приложить отчёт.

## Конфигурация стенда

- API Gateway доступен на `127.0.0.1:8666`, Kafka/PostgreSQL/Redis — только loopback;
- наружу смотрит Nginx;
- HTTPS/TLS 1.3 на Nginx;
- JWT access/refresh, rate-limit логина, object-level auth, audit;
- тестовый администратор `test_admin` предназначен только для демонстрации; не публиковать его в интернет.

## Что проверено

- backend: 194 passed;
- frontend: production build успешен;
- `npm audit`: 0;
- PyJWT login после замены: 200;
- GLPI autofill: данные применяются автоматически после загрузки;
- Node.js в production-runtime отсутствует.

## Остаточные риски

1. OS-пакеты API image: 1 critical/91 high, большая часть без fixed version в текущем base image.
2. Nginx image: 2 high по curl, fix доступен, требуется пересборка base image.
3. Локальный Node.js 24.16.0 устарел; production не затронут, но build-машину нужно обновить.
4. Предыдущий RPM-пакет собран до этих security-исправлений; для демонстрации через браузер он не требуется. Если ставить клиентский RPM — пересобрать.
5. Тестовый стенд не является production perimeter: нет WAF/HA-периметра и отдельного hardening по 4.2.
