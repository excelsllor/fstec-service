# Trivy-скан после обновлений — 2026-10-24

Команда: `trivy image --scanners vuln --severity HIGH,CRITICAL --ignore-unfixed`
(показаны только исправимые уязвимости).

| Образ | CRITICAL | HIGH | Комментарий |
|---|---:|---:|---|
| `services-api-gateway` | 0 | 0 | приложение |
| `services-ingest-service` | 0 | 2 | `opencv-python` / `opencv-contrib-python` из PaddleOCR |
| `services-nginx` | 0 | 0 | frontend |
| `nginxinc/nginx-unprivileged:1.29-alpine` | 0 | 45 | базовые пакеты Alpine |
| `postgres:16-alpine` | 1 | 25 | `stdlib` в образе |
| `redis:7-alpine` | 0 | 2 | `libssl3`/`libcrypto3` |
| `bitnamilegacy/kafka:3.9` | 18 | 121 | Java-зависимости и base-пакеты |

Сырые JSON: `/home/raport/trivy/*.json` на сервере.

Вывод: приложение и frontend чистые по fixable HIGH/CRITICAL. Остаточные риски сосредоточены
в legacy Kafka, базовом PostgreSQL и Alpine-пакетах nginx. Kafka наружу не публикуется
(`127.0.0.1:9092`), но замена образа/обновление Java-зависимостей остаётся задачей.
