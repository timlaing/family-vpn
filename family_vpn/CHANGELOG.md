# 0.6.3

- Simplify push setup to Primary relay or Direct APNs, with optional relay hosting after direct setup.
- Configure direct APNs using separate Key ID, Team ID and private-key file fields.
- Collect hosted relay URL, optional Worker token and rate limit on a separate page, reusing direct Apple credentials.
- Add a dedicated push delivery status page linked from the main dashboard, with back navigation and no credential forms.
- Show last push results and production/sandbox endpoints; ping a random registered device for direct APNs, hiding connectivity controls when no devices have push tokens.
- Add authenticated relay ping and signed callback checks with replay protection and endpoint rate limits.
- Fix hosted relay form markup and retain only Push setup in the navigation menu.

# 0.6.2

- Separate hosted relay administration from dashboard push delivery into dedicated menu pages.
- Configure the public hosted relay HTTPS URL and show its registration and push addresses.
- Provide separate Apple Key ID and Team ID fields with private-key upload or paste; retain saved keys when blank and never display stored private keys.
- Show setup connection failures beside the check buttons in a prominent accessible alert.
- Improve setup progress, password-manager hints and navigation styling.
- Resolve dashboard/relay quality findings and synchronize pinned runtime dependency manifests.

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

# 0.3.5

- Change the default REST port to 8500 across app packaging, proxy generation and standalone deployment. Update existing reverse-proxy upstreams to the configured host mapping after upgrading. Ingress remains on 8099.

# 0.3.4

- Simplify setup wording and single-column form; strengthen branding and stop repeating background graphics.
- Start trusted Wi-Fi empty and render added networks as table rows.
- Upload PEM/DER CA certificates; retain existing certificates unless explicitly replaced or removed.

# 0.3.3

- Gate menu pages and direct links by provisioning, administrator setup and device enrollment prerequisites.
- Edit trusted Wi-Fi with an Add network button and per-network Delete buttons.
- Split dashboard into status/reports, provisioning, administration, commands/activity and configuration pages with an accessible hamburger menu.

# 0.3.2

- Fix VPN provisioning form layout with styled fields and responsive columns.

# 0.3.1

- Generate and persist optional bearer credentials on first startup; retrieve them through authenticated Ingress.
- Configure APNs and policy-check scheduling exclusively in the dashboard, with one-time migration of existing options.

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
