#!/usr/bin/env bash
# Restore PostgreSQL + data volume from a backup created by tools/backup.sh.
# Usage: restore.sh postgres_YYYYMMDD_HHMMSS.sql.gz data_YYYYMMDD_HHMMSS.tgz
set -euo pipefail

PG_FILE="${1:?postgres dump is required}"
DATA_FILE="${2:?data archive is required}"
PG_CONTAINER="${PG_CONTAINER:-fstec-postgres}"
DATA_VOLUME="${DATA_VOLUME:-services_data}"

test -s "$PG_FILE"
test -s "$DATA_FILE"
gzip -t "$PG_FILE"
tar -tzf "$DATA_FILE" >/dev/null

echo "[1/2] PostgreSQL restore"
gunzip -c "$PG_FILE" | docker exec -i "$PG_CONTAINER" sh -lc \
  'psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" "$POSTGRES_DB"'

echo "[2/2] Data volume restore"
docker run --rm -v "${DATA_VOLUME}:/data" -v "$(dirname "$DATA_FILE"):/backup:ro" alpine:3.20 \
  sh -lc "rm -rf /data/* && tar xzf /backup/$(basename "$DATA_FILE") -C /data --strip-components=1"

echo "OK: restore completed"
