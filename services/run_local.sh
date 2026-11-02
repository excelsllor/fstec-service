#!/usr/bin/env bash
# Локальный запуск микросервисов (dev, без Kafka/Redis/Postgres):
# SQLite-шина + SQLite БД + мок CMDB + heuristic LLM.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FSTEC_EVENT_BUS=sqlite
export FSTEC_BUS_POLL_S=0.25
export FSTEC_DATA_DIR="$ROOT/data"
export DATABASE_URL="sqlite:///$ROOT/data/fstec_services.db"
export FSTEC_OCR_ENABLED=false
export FSTEC_LLM_PROVIDER=heuristic
export FSTEC_SECURITY_MODE=mock
export CMDB_PROVIDER=mock
export FSTEC_GATEWAY_PORT=8666
mkdir -p "$ROOT/data/logs"

declare -A SERVICES=(
  [api-gateway]=api_gateway.main
  [ingest]=ingest_service.worker
  [llm]=llm_service.worker
  [security]=security_service.worker
  [reporting]=reporting_service.worker
)

for name in "${!SERVICES[@]}"; do
  python -m "${SERVICES[$name]}" >>"$ROOT/data/logs/$name.log" 2>>"$ROOT/data/logs/$name.err.log" &
  echo "[$name] PID $!"
done

echo ""
echo "Gateway: http://127.0.0.1:8666 (docs /api/docs)"
echo "Логи:    services/data/logs/*.log"
echo "Смоук:   python tools/services_smoke.py  (из services/)"
wait