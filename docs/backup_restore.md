# Резервное копирование и восстановление

## Состав резервной копии

- PostgreSQL: `postgres_<timestamp>.sql.gz` (`pg_dump --clean --if-exists`).
- Файловый volume `services_data`: `data_<timestamp>.tgz` (загрузки, отчёты, исходники).
- Контрольные суммы: `sha256_<timestamp>.txt`.

Каталог по умолчанию: `/home/raport/fstec-backups`.
Хранение: 14 дней (`KEEP_DAYS`), старые копии удаляются автоматически.

Проверка 2026-10-24: `postgres_20261024_175232.sql.gz` + `data_20261024_175232.tgz`,
restore во временную БД `fstec_restore` — 3179 документов, 1 пользователь, затем БД удалена.
Размер копии ~900 МБ; свободное место проверять перед запуском.

## Расписание

Cron пользователя `raport`:

```cron
30 2 * * * cd /home/raport/fstec-service/services && OUT_DIR=/home/raport/fstec-backups KEEP_DAYS=14 ./tools/backup.sh >> /home/raport/fstec-backups/backup.log 2>&1
*/15 * * * * cd /home/raport/fstec-service/services && docker compose exec -T api-gateway python tools/watchdog.py --older-than 60 --mark-failed >> /home/raport/fstec-backups/watchdog.log 2>&1
```

## Проверка копии

```bash
cd /home/raport/fstec-backups
sha256sum -c sha256_<timestamp>.txt
gzip -t postgres_<timestamp>.sql.gz
tar -tzf data_<timestamp>.tgz >/dev/null
```

## Восстановление БД (RTO ≈ 15–30 минут)

```bash
cd /home/raport/fstec-backups
docker exec fstec-postgres psql -U fstec -d postgres -c \
  "DROP DATABASE IF EXISTS fstec_restore; CREATE DATABASE fstec_restore;"
gunzip -c postgres_<timestamp>.sql.gz | \
  docker exec -i fstec-postgres psql -U fstec -d fstec_restore
```

Проверить количество документов/пользователей, затем переключить приложение на восстановленную БД
или переименовать базы в окно обслуживания:

```bash
docker exec fstec-postgres psql -U fstec -d postgres -c \
  "ALTER DATABASE fstec RENAME TO fstec_old; ALTER DATABASE fstec_restore RENAME TO fstec;"
docker compose restart api-gateway ingest-service llm-service security-service reporting-service audit-service
```

Файлы восстанавливаются в новый volume:

```bash
docker volume create services_data_restore
docker run --rm -v services_data_restore:/data -v /home/raport/fstec-backups:/backup alpine:3.20 \
  tar xzf /backup/data_<timestamp>.tgz -C /
```

Затем в `docker-compose.yml` заменить `services_data` на `services_data_restore` и перезапустить сервисы.

## Ограничения

- Копии локальные, на том же сервере. Для защиты от отказа диска/хоста нужен внешний NFS/S3
  или вторая площадка; текущий регламент закрывает восстановление после ошибки приложения/БД,
  но не является HA.
- RPO: до 24 часов (ночной бэкап). RTO: 15–30 минут при исправном сервере.
- После восстановления обязательно проверить вход, список документов, скачивание отчёта и ответа.
