#!/usr/bin/env bash
set -euo pipefail

: "${KAFKA_CLIENT_USERS:?KAFKA_CLIENT_USERS is required}"
: "${KAFKA_CLIENT_PASSWORDS:?KAFKA_CLIENT_PASSWORDS is required}"

cat > /tmp/fstec-kafka-client.properties <<EOF
security.protocol=SASL_SSL
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="${KAFKA_CLIENT_USERS}" password="${KAFKA_CLIENT_PASSWORDS}";
ssl.truststore.location=/bitnami/kafka/config/certs/kafka.truststore.pem
ssl.truststore.type=PEM
EOF

kafka-topics.sh --bootstrap-server localhost:9092 --list \
  --command-config /tmp/fstec-kafka-client.properties >/dev/null
