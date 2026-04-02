#!/usr/bin/env bash
set -euo pipefail

if [ ! -x "build/KleosRelay" ]; then
  ./build.sh
fi

PORT="${KLEOS_RELAY_PORT:-5555}"
MAX_PAYLOAD="${KLEOS_RELAY_MAX_PAYLOAD:-262144}"
BIND="${KLEOS_RELAY_BIND:-127.0.0.1}"
HUB="${KLEOS_HUB:-127.0.0.1:7000}"
PUB_HOST="${KLEOS_RELAY_PUBLIC_HOST:-127.0.0.1}"

KLEOS_HUB="${HUB}" KLEOS_RELAY_PUBLIC_HOST="${PUB_HOST}" KLEOS_RELAY_PUBLIC_PORT="${PORT}" \
  ./build/KleosRelay "${PORT}" "${MAX_PAYLOAD}" "${BIND}" &
RELAY_PID="$!"

cleanup() {
  kill "${RELAY_PID}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cd elixir/kleos_hub
iex --sname "${KLEOS_HUB_NODE:-kleos_hub}" --cookie "${KLEOS_COOKIE:-kleos}" -S mix
