#!/usr/bin/env bash
set -euo pipefail

if [ -z "${SDKROOT:-}" ] && [ -d "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk" ]; then
  export SDKROOT="/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk"
fi

cmake -S . -B build
cmake --build build -j

cd elixir/kleos_hub
mix deps.get
mix compile
