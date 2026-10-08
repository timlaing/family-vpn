#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
venv="${DEV_VENV:-.venv}"
python_bin="${DEV_PYTHON:-python3}"
"$python_bin" -c 'import sys; assert (3, 12) <= sys.version_info[:2] <= (3, 14), "Use Python 3.12–3.14"'
if [[ ! -x "$venv"/bin/python ]]; then "$python_bin" -m venv "$venv"; fi
"$venv"/bin/python -m pip install --only-binary=:all: -r requirements-dev.txt
"$venv"/bin/python -m pip check
"$venv"/bin/python scripts/sync_prek_deps.py --check requirements-test.txt
"$venv"/bin/python scripts/check_runtime_locks.py
if [[ "${INSTALL_HOOKS:-1}" == 1 ]]; then "$venv"/bin/prek install; fi
