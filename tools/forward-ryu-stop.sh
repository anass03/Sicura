#!/usr/bin/env bash
set -euo pipefail

HOST_PORT="${HOST_PORT:-8080}"
SIDECAR_NAME="ryu-forward-${HOST_PORT}"

if docker ps -a --format '{{.Names}}' | grep -q "^${SIDECAR_NAME}\$"; then
  docker rm -f "${SIDECAR_NAME}" >/dev/null
  echo "Forward fermato (container ${SIDECAR_NAME} rimosso)."
else
  echo "Nessun forward attivo (${SIDECAR_NAME} non trovato)."
fi
