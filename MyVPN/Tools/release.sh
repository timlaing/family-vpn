#!/bin/bash
# Signed local archives. Signing assets and notary credentials stay in Apple tooling.
set -euo pipefail
cd "$(dirname "$0")/.."
platform="${1:-}"
output="${2:-}"
if [[ "$platform" != ios && "$platform" != macos ]] || [[ -z "$output" || "$output" != /* ]]; then
    echo 'Usage: Tools/release.sh ios|macos /absolute/output-directory' >&2
    exit 2
fi
if [[ -e "$output" ]]; then
    echo 'Choose a new output directory to preserve existing release artifacts.' >&2
    exit 2
fi
mkdir -p "$output"
if [[ "$platform" == ios ]]; then
    destination='generic/platform=iOS'
    options=Config/ExportOptions/iOS-AdHoc.plist
else
    destination='generic/platform=macOS'
    options=Config/ExportOptions/macOS-DeveloperID.plist
fi
xcodebuild -project MyVPN.xcodeproj -scheme MyVPN -configuration Release \
    -destination "$destination" -archivePath "$output/MyVPN.xcarchive" \
    -allowProvisioningUpdates archive
xcodebuild -exportArchive -archivePath "$output/MyVPN.xcarchive" \
    -exportPath "$output/export" -exportOptionsPlist "$options" -allowProvisioningUpdates
if [[ "$platform" == macos ]]; then
    app="$output/export/MyVPN.app"
    codesign --verify --deep --strict "$app"
    if [[ -z "${NOTARY_KEYCHAIN_PROFILE:-}" ]]; then
        echo 'Export complete; notarization is pending. Set NOTARY_KEYCHAIN_PROFILE for a notarized release.' >&2
        exit 3
    fi
    ditto -c -k --keepParent "$app" "$output/MyVPN.zip"
    xcrun notarytool submit "$output/MyVPN.zip" --keychain-profile "$NOTARY_KEYCHAIN_PROFILE" --wait
    xcrun stapler staple "$app"
    xcrun stapler validate "$app"
    spctl --assess --type execute "$app"
    ditto -c -k --keepParent "$app" "$output/MyVPN-notarized.zip"
fi
