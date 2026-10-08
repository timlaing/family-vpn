#!/bin/sh
# Xcode Cloud runs native tests itself; this hook verifies the profile importer.
set -eu
cd "${CI_PRIMARY_REPOSITORY_PATH:?Xcode Cloud repository path is required}"
python3 -m unittest discover -s MyVPN/Tools -v
