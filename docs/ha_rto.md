# HA и RTO: текущее состояние

## Что сделано

- `restart: unless-stopped` для всех сервисов, healthchecks и автоперезапуск контейнеров.
- Ежедневный backup PostgreSQL + `services_data` (cron 02:30, retention 14 дней).
- Restore-тест: временная БД `fstec_restore` восстановлена из дампа (3179 документов, 1 пользователь).
- Watchdog каждые 15 минут переводит зависшие (>60 мин) документы в `failed`.
- Kafka: отдельный volume `services_kafka_data`, SASL_SSL, healthcheck.
- Целевые показатели текущей схемы: **RPO ≤24 ч, RTO 15–30 мин** при исправном сервере.

## Чего нет

Полноценного HA на одном физическом хосте нет: Kafka, PostgreSQL и приложение имеют единую точку отказа
(сервер/диск). Docker restart не спасает при отказе хоста или потере диска.
Для SLA 99,5% нужны минимум два хоста и внешнее хранилище/балансировщик.

## Что нужно для настоящего HA

1. Второй сервер (или 3 узла для etcd/Patroni) в другой зоне/стойке.
2. PostgreSQL: Patroni + etcd, синхронная реплика, VIP/HAProxy.
3. Kafka: минимум 3 брокера, replication factor 3, min.insync.replicas 2.
4. Общий/реплицируемый storage для `services_data` (NFS/Ceph/S3) или object storage.
5. Внешний балансировщик с health-check и TLS-терминацией.
6. Внешние бэкапы (S3/NFS), регулярный restore-drill и мониторинг RPO/RTO.

## Ручной failover при отказе приложения

```bash
cd /home/raport/fstec-service/services
docker compose ps
docker compose restart api-gateway ingest-service security-service reporting-service audit-service nginx
```

При потере БД — восстановление по `docs/backup_restore.md`. При потере Kafka volume
очередь событий не восстанавливается; документы и отчёты в PostgreSQL/`services_data` сохраняются,
но незавершённые документы нужно перезагрузить.
