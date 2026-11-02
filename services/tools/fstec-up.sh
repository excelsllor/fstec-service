#!/usr/bin/env bash
# Decrypt host-bound secrets to tmpfs and start the stack after boot.
set -euo pipefail

PUBLIC=/home/raport/fstec-service/services/.env.public
SECRET=/etc/fstec/secrets.cred
RUN_DIR=/run/fstec
OUT="$RUN_DIR/compose.env"

install -d -m 0750 -g raport "$RUN_DIR"
rm -f "$RUN_DIR/secrets.env" "$OUT"
systemd-creds decrypt --name=fstec-secrets "$SECRET" "$RUN_DIR/secrets.env"
cat "$PUBLIC" "$RUN_DIR/secrets.env" > "$OUT"
rm -f "$RUN_DIR/secrets.env"
chown root:raport "$OUT"
chmod 0640 "$OUT"

if [ "${1:-}" = "--prepare-only" ]; then
  exit 0
fi

cd /home/raport/fstec-service/services
compose() {
  docker compose -f docker-compose.yml -f docker-compose.t4.yml "$@"
}

compose up -d --no-deps kafka redis postgres
sleep 5
compose up -d --no-deps vllm-proxy api-gateway ingest-service llm-service security-service reporting-service audit-service
sleep 5
compose up -d --no-deps nginx
