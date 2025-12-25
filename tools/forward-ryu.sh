#!/usr/bin/env bash
set -euo pipefail

HOST_BIND="${HOST_BIND:-127.0.0.1}"
HOST_PORT="${HOST_PORT:-8080}"
TARGET_PORT="${TARGET_PORT:-8080}"

SIDECAR_NAME="ryu-forward-${HOST_PORT}"
CTRL_CONTAINER="$(docker ps --format '{{.Names}}' | grep '_ctrl_' | head -n1 || true)"

if [ -z "${CTRL_CONTAINER}" ]; then
  echo "Container ctrl non trovato (docker ps | grep _ctrl_)." >&2
  exit 1
fi

# Se esiste già, non duplicare
if docker ps --format '{{.Names}}' | grep -q "^${SIDECAR_NAME}\$"; then
  echo "Forward già attivo tramite container ${SIDECAR_NAME}."
  exit 0
fi

# Se il nome esiste ma è fermo, rimuovi
if docker ps -a --format '{{.Names}}' | grep -q "^${SIDECAR_NAME}\$"; then
  docker rm -f "${SIDECAR_NAME}" >/dev/null 2>&1 || true
fi

echo "Avvio forward: ${HOST_BIND}:${HOST_PORT} -> (netns di ${CTRL_CONTAINER}) 127.0.0.1:${TARGET_PORT}"
docker run -d --name "${SIDECAR_NAME}" \
  --restart unless-stopped \
  -p "${HOST_BIND}:${HOST_PORT}:${HOST_PORT}" \
  --network "container:${CTRL_CONTAINER}" \
  alpine/socat -d -d \
  "TCP-LISTEN:${HOST_PORT},fork,reuseaddr" "TCP:127.0.0.1:${TARGET_PORT}" >/dev/null

echo "OK. Test: curl http://${HOST_BIND}:${HOST_PORT}/api/firewall/status"
