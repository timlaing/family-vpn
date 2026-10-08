#!/bin/bash
# Reproducible verification. No VPN installation, certificate trust or live APNs calls.
set -euo pipefail
cd "$(dirname "$0")/.."
watchdog_python="${WATCHDOG_PYTHON:-.venv/bin/python}"
if [[ ! -x "$watchdog_python" ]]; then
    echo 'Create a test environment with ../requirements-test.txt, or set WATCHDOG_PYTHON.' >&2
    exit 1
fi
"$watchdog_python" -c 'import httpx, cryptography, pytest'
evidence="$(mktemp -d /tmp/FamilyVPN-verification.XXXXXX)"
echo "Verification logs: $evidence"
trap 'echo "Verification stopped; inspect logs in $evidence" >&2' ERR
"$watchdog_python" -m pytest Tools -v > "$evidence/importer.log" 2>&1
"$watchdog_python" -m pytest Watchdog -v > "$evidence/watchdog.log" 2>&1
xcodebuild -project FamilyVPN.xcodeproj -scheme FamilyVPN -destination 'platform=macOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO test > "$evidence/mac-tests.log" 2>&1
xcodebuild -project FamilyVPN.xcodeproj -scheme FamilyVPN -destination 'generic/platform=iOS Simulator' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- build > "$evidence/simulator.log" 2>&1
if [[ -n "${SIMULATOR_TEST_DEVICE_ID:-}" ]]; then
    xcodebuild -project FamilyVPN.xcodeproj -scheme FamilyVPN -destination "platform=iOS Simulator,id=$SIMULATOR_TEST_DEVICE_ID" \
        -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=YES CODE_SIGN_IDENTITY=- test > "$evidence/simulator-tests.log" 2>&1
fi
xcodebuild -project FamilyVPN.xcodeproj -scheme FamilyVPN -configuration Release -destination 'generic/platform=iOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO build > "$evidence/ios-release.log" 2>&1
xcodebuild -project FamilyVPN.xcodeproj -scheme FamilyVPN -configuration Release -destination 'platform=macOS' \
    -derivedDataPath "$evidence/DerivedData" CODE_SIGNING_ALLOWED=NO build > "$evidence/mac-release.log" 2>&1
echo "Verification passed. Logs: $evidence"
