# 0.3.0

- Move device administrator password setup to the dashboard and provision its verifier during registration.
- Register iOS/macOS before VPN installation; preserve existing APNs tokens and avoid repeated enrollment rotation.
- Add signed administrator reprovision requests with independent replay/supersession, snapshots and acknowledgements.

# 0.2.0

- Signed refresh, suspend and enable requests with durable acknowledgements.
- Public authenticated status/acknowledgement exceptions, rate limits and separate protected-contact tracking.

# Changelog

## 0.1.0

### Added

- Authenticated dashboard with per-installation and all-device APNs policy-check requests.
- Scheduled background hints, invalid-token handling and race-safe token rotation.
- Device-scoped status credentials and minimal connection/policy reports.
- Private SQLite storage and bounded operational history.
- Read-only preview and 22 isolated service tests, including ES256 JWT verification.
- MIT licence, contribution/security guides, API/architecture/deployment documentation.
- Non-root Docker image, container smoke test and GitHub Actions CI/image publication.

No production APNs delivery or physical-device execution has been established by synthetic tests.

- Home Assistant app packaging with protected Ingress dashboard/configuration, isolated REST listener and NPM path-prefix instructions.

- VPN-only REST deployment policy, including private routing, proxy source restrictions and stale-report semantics.

- Validated NPM location generator and end-to-end allowed/denied REST source checks.
