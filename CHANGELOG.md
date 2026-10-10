# Unreleased

- Support external EAP-RADIUS authentication in the standalone endpoint UI and CLI, with optional accounting, private shared-secret storage and no local fallback.

- Set the standalone endpoint administrator password through first-launch setup; preserve existing credentials.
- Add Family VPN shield/network graphics and a separate device accounts page with disabling, enabling, deletion and password changes.

- Add a standalone strongSwan browser setup/account interface with persistent Docker volumes, protected administrator login and public CA download.
- Keep CA signing keys outside the VPN container and test browser provisioning, volume persistence and CLI compatibility in CI.

# 0.6.0

- Add a guided published-app setup flow, copy-ready reverse-proxy configuration, and one-use HTTPS connectivity checks.
- Enroll devices with ten-minute single-use QR codes/setup links and device-scoped registration credentials.
- Support native setup links, iOS QR scanning, and explicit dashboard confirmation with manual enrollment retained for older deployments.
- Add a separate Linux strongSwan Docker/Compose endpoint with private certificate/account generation and deployment instructions.

# 0.5.2

- Enable automatic policy checks by default; start their interval only after a push-capable device registers and push delivery is ready.
- Preserve explicitly saved policy preferences and show waiting status during setup.

# 0.5.1

- Clarify Primary relay and Direct APNs choices, with independent optional relay hosting.
- Validate the Worker header only when a host credential is configured; support Workers without a proxy secret.

# 0.5.0

- Host the primary push relay inside the HA app and configure publisher credentials through private Ingress uploads.
- Add Primary/Custom setup, direct Apple-only custom APNs, and a shared REST address for callbacks.
- Authenticate the Worker with a private injected credential; enforce duplicate registration rejection, daily key rotation with recovery, and 30-day inactivity expiry.
- Simplify push settings and preserve policy checks in Administration.

# 0.4.0

- Add configurable published-app relay and direct APNs modes under Advanced.
- Register VPN endpoints with signed requests, callback ownership verification and durable replay protection.
- Limit requests per endpoint (10/minute default), forward signed push results to the owner dashboard, and retain no device records on the relay.

# 0.3.0

- Move device administrator password setup to the dashboard and provision its verifier during registration.
- Register iOS/macOS before VPN installation; preserve existing APNs tokens and avoid repeated enrollment rotation.
- Add signed administrator reprovision requests with independent replay/supersession, snapshots and acknowledgements.

# 0.2.0

- Signed refresh, suspend and enable requests with durable acknowledgements.
- Public authenticated status/acknowledgement exceptions, rate limits and separate protected-contact tracking.

# Changelog

## Unreleased

- Add SHA-pinned pre-commit hooks with prek, dependency-sync checks, Python setup/preview scripts and a validated Python 3.14 devcontainer.

- Update runtime dependencies to cryptography 50.0.2, Gunicorn 26.2.0 and pycparser 3.1; allow patched cryptography in the legacy watchdog.

- Add repository metadata/topics/labels, issue triage, PR labeling, release drafts, stale issue handling, CodeQL and Home Assistant app/workflow lint.
- Add one-click Home Assistant repository installation and clarify source builds, updates and gateway setup.
- Fix Linux add-on smoke tests to use Supervisor-style root-owned data with all capabilities dropped.

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
