#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
venv="${DEV_VENV:-.venv}"
if [[ ! -x "$venv"/bin/python ]]; then
  echo 'Run scripts/setup.sh first.' >&2
  exit 1
fi
"$venv"/bin/python -m pip check
"$venv"/bin/python scripts/check_runtime_locks.py
"$venv"/bin/python scripts/sync_prek_deps.py --check requirements-test.txt
echo 'Development environment ready. Use scripts/dev.sh for the synthetic dashboard preview.'
