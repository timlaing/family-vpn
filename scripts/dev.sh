#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
venv="${DEV_VENV:-.venv}"
if [[ ! -x "$venv"/bin/python ]]; then
  echo 'Run scripts/setup.sh first.' >&2
  exit 1
fi
exec "$venv"/bin/python app.py --demo --port "${PREVIEW_PORT:-8500}"
