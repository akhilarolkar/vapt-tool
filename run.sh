#!/usr/bin/env bash
set -euo pipefail

# Portable runner for the FastAPI app
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT_DIR/.venv"

if [ ! -d "$VENV_DIR" ]; then
	python3 -m venv "$VENV_DIR"
fi

# shellcheck source=/dev/null
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
if [ -f "$ROOT_DIR/requirements.txt" ]; then
	pip install -r "$ROOT_DIR/requirements.txt"
fi

# Defaults (can be overridden via env vars)
HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8000}"
RELOAD="${RELOAD:-false}"

if [ "$RELOAD" = "true" ] || [ "$RELOAD" = "1" ]; then
	uvicorn app.main:app --host "$HOST" --port "$PORT" --reload
else
	uvicorn app.main:app --host "$HOST" --port "$PORT"
fi

