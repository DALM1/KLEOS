#!/usr/bin/env bash
set -euo pipefail

cmake -S . -B build
cmake --build build -j

cd elixir/kleos_hub
mix deps.get
mix compile
