# TLS и Kafka SASL_SSL

## Nginx / внешний HTTPS

- HTTP: `:8080` только `/healthz`, остальное — 301 на HTTPS; HTTPS: `:8443` (host `443`).
- Протоколы: TLS 1.2 и TLS 1.3; проверено `TLSv1.3 / TLS_AES_256_GCM_SHA384`.
- Сертификат: `/home/raport/fstec-service/certs/server.crt`, SAN `fstec.local`, `10.248.55.161`.
- Ключ: `server.key` (0600, uid 101 nginx).
- CA: `/home/raport/fstec-service/certs/ca.crt`, SHA-256 fingerprint
  `8F:36:C8:73:E3:29:7E:D6:FB:C9:03:48:FD:03:3B:7E:9F:26:16:37:49:56:3A:3D:E2:A9:93:E8:82:DB:86:81`.
- Срок действия сертификатов: до `2029-01-26`.

Проверка:

```bash
curl -vk --resolve fstec.local:443:10.248.55.161 https://fstec.local/
openssl s_client -connect 10.248.55.161:443 -tls1_3 -servername fstec.local \
  -CAfile certs/ca.crt </dev/null 2>/dev/null | grep -E 'Protocol|Cipher|Verify return code'
```

Клиентам нужно добавить `ca.crt` в доверенные (или использовать сертификат от корпоративного УЦ).
Для продакшена рекомендуется заменить self-signed CA на сертификат УЦ, не меняя конфиг nginx.

## Kafka

- Listener: `INTERNAL://:9092`, протокол `SASL_SSL`.
- SASL: `PLAIN` поверх TLS (пароль внутри шифрованного канала).
- Controller `:9093` — `PLAINTEXT` только внутри Docker-сети, наружу не публикуется.
- Сертификаты:
  - `certs/kafka.keystore.pem` (SAN `kafka`, `localhost`, `127.0.0.1`);
  - `certs/kafka.keystore.key` (0600, uid 1001);
  - `certs/ca.crt` как truststore.
- Пароли: `KAFKA_SASL_PASSWORD` и `KAFKA_INTER_BROKER_PASSWORD` в `services/.env` (0600),
  сгенерированы `openssl rand -hex 24`.
- Проверка: `docker exec fstec-kafka /usr/local/bin/kafka-healthcheck.sh`.

Клиенты читают `KAFKA_SECURITY_PROTOCOL=SASL_SSL`, `KAFKA_SASL_MECHANISM=PLAIN`,
`KAFKA_SASL_USERNAME`, `KAFKA_SASL_PASSWORD`, `KAFKA_SSL_CA_FILE`; CA монтируется
в `/etc/fstec/kafka-ca.crt` через compose `configs`.

## Ротация паролей Kafka

1. Сгенерировать новые пароли и обновить `KAFKA_SASL_PASSWORD`/`KAFKA_INTER_BROKER_PASSWORD` в `.env`.
2. Остановить сервисы-клиенты и Kafka.
3. Поднять Kafka, затем сервисы; проверить healthcheck и обработку одного документа.
4. Старые пароли нигде не сохранять; `.env` остаётся 0600.

## Продление сертификатов

Сертификаты подписаны внутренним CA. При продлении:

```bash
cd /home/raport/fstec-service/certs
# повторить выпуск server.* и/или kafka.* с теми же SAN
docker restart fstec-nginx fstec-kafka
```

После перезапуска Kafka клиенты переподключатся автоматически; при смене CA нужно
обновить `ca.crt` во всех контейнерах (compose `configs`) и перезапустить сервисы.

## vLLM TLS

vLLM на хосте слушает `172.17.0.1:8000` (HTTP). Контейнер `fstec-vllm-proxy` принимает HTTPS
на `vllm-proxy:8443`, проверяет серверный сертификат `vllm.crt` (SAN `vllm-proxy`) и проксирует
запросы к vLLM. Клиенты (`llm-service`, `api-gateway`, `reporting-service`) используют
`VLLM_BASE_URL=https://vllm-proxy:8443/v1` и `VLLM_CA_FILE=/etc/fstec/vllm-ca.crt`.
Проверка: `docker exec fstec-llm python -c "from llm_service.provider import get_provider; print(get_provider().warmup())"`.

## Ограничения

- vLLM наружу не публикуется; доступ только через TLS-прокси внутри Docker-сети.
- CMDB GLPI использует HTTPS, проверка сертификата выполняется клиентом.
- Полноценный HA Kafka/Postgres на одном хосте невозможен; текущая схема — single-node
  с TLS/SASL, автоматическими бэкапами и watchdog.
