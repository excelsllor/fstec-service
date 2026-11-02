#!/usr/bin/env bash
# PostgreSQL + data volume backup with retention and integrity checks.
set -euo pipefail

OUT_DIR="${OUT_DIR:-/home/raport/fstec-backups}"
PG_CONTAINER="${PG_CONTAINER:-fstec-postgres}"
DATA_VOLUME="${DATA_VOLUME:-services_data}"
KEEP_DAYS="${KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d_%H%M%S)"
LOCK_DIR="$OUT_DIR/.lock"

mkdir -p "$OUT_DIR"
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Backup already running ($LOCK_DIR)" >&2
  exit 1
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

PG_TMP="$OUT_DIR/postgres_${STAMP}.sql.gz.part"
DATA_TMP="$OUT_DIR/data_${STAMP}.tgz.part"

echo "[1/3] PostgreSQL"
docker exec "$PG_CONTAINER" sh -lc 'pg_dump --clean --if-exists -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  | gzip -9 > "$PG_TMP"
gzip -t "$PG_TMP"
mv "$PG_TMP" "${PG_TMP%.part}"

echo "[2/3] Files ($DATA_VOLUME)"
docker run --rm -v "${DATA_VOLUME}:/data:ro" -v "$OUT_DIR:/backup" alpine:3.20 \
  tar czf "/backup/$(basename "$DATA_TMP")" -C / data
tar -tzf "$DATA_TMP" >/dev/null
mv "$DATA_TMP" "${DATA_TMP%.part}"

echo "[3/3] Checksums and retention (${KEEP_DAYS}d)"
cd "$OUT_DIR"
sha256sum "postgres_${STAMP}.sql.gz" "data_${STAMP}.tgz" > "sha256_${STAMP}.txt"
find "$OUT_DIR" -maxdepth 1 -type f \( -name 'postgres_*.sql.gz' -o -name 'data_*.tgz' \
  -o -name 'sha256_*.txt' \) -mtime +"$KEEP_DAYS" -delete

echo "OK: $OUT_DIR/postgres_${STAMP}.sql.gz, $OUT_DIR/data_${STAMP}.tgz"
