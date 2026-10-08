# Xcode Cloud

Use Xcode Cloud for Apple builds, XCTest, archives and distribution. Keep the Python service's existing GitHub Actions workflows for service tests and container publishing.

## Activate

1. Publish this repository to a supported hosted Git provider. No Git remote is currently configured. Commit and push the shared `MyVPN` scheme and `ci_scripts` directory.
2. In Xcode, sign into the intended Apple Developer team, open `MyVPN.xcodeproj`, then choose Product → Xcode Cloud → Create Workflow. Authorize repository access and select the shared MyVPN scheme. This account/repository authorization cannot be activated by local files alone.
3. Configure the App ID `uk.co.laingcorp.myvpn` with Personal VPN and Push Notifications. Enable Access Wi-Fi Information for iOS. Refresh automatic signing profiles after changing capabilities. macOS declares `com.apple.developer.aps-environment`; iOS declares `aps-environment`. Distribution signing must use production APNs entitlements and the dashboard must use the matching APNs environment.
4. Create the workflows below. Choose available stable Xcode/macOS versions compatible with the deployment targets; review them after each OS release.

| Workflow | Start condition | Actions |
| --- | --- | --- |
| iOS validation | Pull requests and changes to the main branch | Analyze; Test on an iPhone and iPad simulator |
| macOS validation | Pull requests and changes to the main branch | Analyze; Test on macOS |
| iOS release | Release tag or manual start | Archive iOS; distribute to an internal TestFlight group |
| macOS release | Release tag or manual start | Archive macOS for direct distribution; enable notarization post-action |

`ci_scripts/ci_post_clone.sh` additionally runs importer tests without third-party dependencies. XCTest is configured in the shared scheme. Do not run `Tools/verify.sh` inside the hook: it starts nested Xcode builds and also expects local watchdog dependencies.

TestFlight requires an App Store Connect app record. Ad hoc installation can instead use the existing release-testing export configuration with registered device UDIDs. Direct macOS distribution requires Developer ID signing and successful notarization. Do not enable automatic external publishing until the physical acceptance checklist passes.

## Release verification

Download the release artifacts. Verify the Mac's signature with `codesign --verify --deep --strict`, notarization with `spctl --assess --type execute`, and its stapled ticket with `xcrun stapler validate`. Install in `/Applications`, enable the background monitor, and test APNs with the UI closed and the helper running. Test an iPhone/iPad release build using the real gateway and production APNs provider. Keep certificates, APNs keys and passwords out of the repository and build logs.

## References

- https://developer.apple.com/documentation/xcode/configuring-your-first-xcode-cloud-workflow
- https://developer.apple.com/documentation/xcode/writing-custom-build-scripts
- https://developer.apple.com/documentation/xcode/creating-a-workflow-that-builds-your-app-for-distribution

## Local release alternative

Run `Tools/release.sh ios /absolute/new-release-directory` for an ad hoc signed IPA, or `NOTARY_KEYCHAIN_PROFILE=your-profile Tools/release.sh macos /absolute/new-release-directory` for a signed, notarized Mac ZIP. Store the notary credentials yourself with Apple's `notarytool store-credentials`; the script uses the profile name and never accepts plaintext passwords. Existing output directories are rejected. Without a notary profile the Mac export exits with status 3 and explicitly remains pending notarization.
