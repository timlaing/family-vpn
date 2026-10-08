#!/bin/bash
# Reproducible verification. No VPN installation, certificate trust or live APNs calls.
set -euo pipefail
cd "$(dirname "$0")/.."
watchdog_python="${WATCHDOG_PYTHON:-.venv/bin/python}"
if [[ ! -x "$watchdog_python" ]]; then
    echo 'Create .venv and install Watchdog/requirements.txt, or set WATCHDOG_PYTHON.' >&2
    exit 1
fi
"$watchdog_python" -c 'import httpx, cryptography'
evidence="$(mktemp -d /tmp/FamilyVPN-verification.XXXXXX)"
echo "Verification logs: $evidence"
trap 'echo "Verification stopped; inspect logs in $evidence" >&2' ERR
python3 -m unittest discover -s Tools -v > "$evidence/importer.log" 2>&1
"$watchdog_python" -m unittest discover -s Watchdog -v > "$evidence/watchdog.log" 2>&1
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -destination 'platform=macOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO test > "$evidence/mac-tests.log" 2>&1
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- build > "$evidence/simulator.log" 2>&1
if [[ -n "${SIMULATOR_TEST_DEVICE_ID:-}" ]]; then
    xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -destination "platform=iOS Simulator,id=$SIMULATOR_TEST_DEVICE_ID" \
        -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test > "$evidence/simulator-tests.log" 2>&1
fi
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -configuration Release -destination 'generic/platform=iOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO build > "$evidence/ios-release.log" 2>&1
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -configuration Release -destination 'platform=macOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO build > "$evidence/mac-release.log" 2>&1
echo "Verification passed. Logs: $evidence"
