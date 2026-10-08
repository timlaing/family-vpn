#!/bin/sh
# Xcode Cloud runs native tests; verify the profile importer with isolated pytest.
set -eu
cd "${CI_PRIMARY_REPOSITORY_PATH:?Xcode Cloud repository path is required}"
pytest_env="$(mktemp -d)"
trap 'rm -rf "$pytest_env"' EXIT
python3 -m venv "$pytest_env"
"$pytest_env/bin/python" -m pip install -r requirements-pytest.lock
"$pytest_env/bin/python" -m pytest MyVPN/Tools -v
