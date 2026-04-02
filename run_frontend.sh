#!/usr/bin/env bash
set -euo pipefail

if [ ! -x "build/KleosClient" ]; then
  ./build.sh
fi

export KLEOS_SERVER_HOST="${KLEOS_SERVER_HOST:-127.0.0.1}"
export KLEOS_SERVER_PORT="${KLEOS_SERVER_PORT:-5555}"

./build/KleosClient
