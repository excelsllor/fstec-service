#!/usr/bin/env bash
# Operational HA/RTO readiness check. This is not a replacement for multi-node HA.
set -euo pipefail

OUT_DIR="${OUT_DIR:-/home/raport/fstec-backups}"
fail=0

check() {
  name="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "OK   $name"
  else
    echo "FAIL $name"; fail=1
  fi
}

check "postgres" docker exec fstec-postgres sh -lc 'pg_isready -U "$POSTGRES_USER" -d "$POSTGRES_DB"'
check "redis" docker exec fstec-redis redis-cli -a "$REDIS_PASSWORD" ping
check "api" curl -fsS http://127.0.0.1:8666/api/health
check "kafka" bash -lc "docker inspect --format '{{.State.Health.Status}}' fstec-kafka | grep -qx healthy"

echo "--- containers ---"
docker ps --format '{{.Names}} {{.Status}}' | grep '^fstec-' || true

echo "--- latest backup ---"
latest=$(find "$OUT_DIR" -maxdepth 1 -type f -name 'postgres_*.sql.gz' -printf '%T@ %p\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2- || true)
if [ -n "$latest" ] && [ -s "$latest" ]; then
  age_h=$(( ( $(date +%s) - $(stat -c %Y "$latest") ) / 3600 ))
  echo "OK   backup=$latest age_h=${age_h}"
else
  echo "FAIL no PostgreSQL backup"; fail=1
fi

exit "$fail"
