# HTTP API

All real-device endpoints require HTTPS. Registration is restricted to your configured registration LAN by the reverse proxy. Status and acknowledgements are authenticated public POST routes; remaining REST routes require the VPN subnets. If using a deployment prefix, registration and status must share the same prefix and origin. JSON bodies are limited to 2048 bytes; extra fields are rejected. Installation IDs are canonical lowercase UUIDs. Bearer credentials are case-sensitive. Do not place credentials in URL parameters.

| Route | Authentication | Success |
| --- | --- | --- |
| GET /health | None | 200 `{ "status": "ok" }` |
| POST /registrations | REGISTRATION_BEARER | 201 reporting credential plus requested provisioning fields (see below) |
| POST /status | Device-specific status credential | 204, empty body |
| GET /api/devices | ADMIN_BEARER or standalone admin session | 200 `{ "devices": [...] }` |
| POST /api/push | ADMIN_BEARER only | 202 `{ "result": "queued" }` |
| GET /commands?id=UUID | Device-specific reporting credential | 200 `{ "commands": [...] }` |
| POST /command-results | Device-specific reporting credential | 204, empty body |
| GET /vpn-configuration?id=UUID&request_id=UUID | Device-specific reporting credential | 200 pending VPN configuration snapshot |
| GET /api/commands | ADMIN_BEARER or standalone admin session | 200 `{ "commands": [...] }` |
| POST /api/commands | ADMIN_BEARER only | 202 `{ "result": "pending", "request_id": "UUID" }` |

Send `Authorization: Bearer <credential>` and `Content-Type: application/json` for JSON POST requests. Cookie authentication alone cannot trigger `/api/push`. Dashboard `/push` and `/command` use an administrator session and CSRF nonce instead. In Home Assistant mode these UI routes are available only through Ingress; the external listener rejects browser login and dashboard routes. Only POST `/status` and `/command-results` are public through the configured proxy. Registration requires the registration LAN; other routes require VPN source addresses. The app does not enforce source-subnet ACLs itself.

## Enrollment

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","token":"abababababababababababababababababababababababababababababababab"}
```

Updated native clients send all three headers:

```http
X-FamilyVPN-Command-Protocol: 1
X-FamilyVPN-Administrator-Protocol: 1
X-FamilyVPN-VPN-Protocol: 2
```

The 201 response contains `status_token`, `command_key` (base64 Ed25519 public key), `command_epoch` (UUID), `administrator` (salted password verifier and revision), and `vpn` (gateway, certificate identity, Wi-Fi list, revision and optional public CA). See [administrator provisioning](ADMINISTRATION.md) and [VPN provisioning](PROVISIONING.md) for field formats. Missing administrator or VPN setup returns 409 before rotating credentials.

`token` may be null when administrator protocol 1 is requested, allowing enrollment before APNs registration. An existing APNs token is preserved when null is supplied; otherwise the registered token is updated. Without a token the device cannot receive pushes, but can retrieve pending commands over the VPN.

The example token is synthetic. Actual tokens must be lowercase byte-pair hexadecimal, with variable length. Every successful registration rotates the installation's reporting credential, resets its advertised command capabilities and supersedes old pending commands; command protocol 1 also creates a new enrollment epoch. Store the returned credential in device-only Keychain; it cannot be retrieved later from the server. The updated native app requires the administrator provisioning protocol described in ADMINISTRATION.md; a legacy 204 response cannot provision it.

## Status

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","connection":"connected","policy_ok":true}
```

Connection values: `connected`, `connecting`, `reasserting`, `disconnecting`, `disconnected`, `invalid`. `policy_ok` must be a JSON Boolean, not a number/string. A credential for one installation cannot report for another. Report receipt time is assigned by the server. `policy_ok` describes local policy validation/recovery, not an audited traffic tunnel.

## Administrative device list

Each row includes `id`, `registered`, `seen`, `connection`, `policy_ok`, `pushed`, `push_result`, `registered_token`, `command_capable`, `administrator_capable`, `vpn_capable`, and `tunnel_seen`. Timestamps are Unix seconds; fields without a result can be null. `policy_ok` and `registered_token` are SQLite-derived 0/1 values. Token and status hashes are excluded.

## Triggering checks

Send `{}` to request all registered tokens, or `{ "id": "11223344-5566-7788-9900-aabbccddeeff" }` for one installation. A 202 response queues work and does not wait for Apple or the device. An installation with a cleared token remains in the list but has no deliverable token.

Result codes: `accepted`, `invalid_token`, `retry_later`, `provider_error`, `network_error`, `not_configured`. Apple acceptance is distinct from device reporting. The server stores bounded categories rather than raw provider errors or private request data.

## Failure responses

| Status | Meaning |
| --- | --- |
| 400 | Invalid shape, UUID, token, connection or Boolean |
| 401 | Missing/incorrect administrative, enrollment or scoped report credential |
| 403 | CSRF rejection or attempted write in preview mode |
| 404 | Unknown installation requested for a push |
| 409 | Dispatch busy, missing provisioning, unsupported device capability, or conflicting acknowledgement |
| 413 | Body exceeds 2048 bytes |
| 429 | Dashboard login throttled: five failures per minute/address |
| 503 | APNs provider configuration absent |

Validation failures may precede authentication on `/status`; error bodies are not a stable API contract. Treat status codes as the contract and never assume all errors are JSON. `/health` is process liveness, not end-to-end readiness.

## VPN provisioning

Registration clients send `X-FamilyVPN-VPN-Protocol: 2`. Successful responses include `vpn` with `server`, `remoteIdentifier`, `trustedSSIDs` and UUID `revision`. The dashboard must have valid gateway settings first; otherwise registration returns 409 without rotating credentials. Configuration is managed through the authenticated, CSRF-protected dashboard. See [PROVISIONING.md](PROVISIONING.md).

`reprovision_vpn` commands include `vpn_digest`, a signed SHA-256 hash of a configuration snapshot. Authenticated `GET /vpn-configuration?id=UUID&request_id=UUID` returns the exact pending snapshot only for its device and enrollment epoch. Keep this route VPN-only. `vpn.caCertificate` is optional base64 DER, supplied through a validated PEM CA in the dashboard.

## Signed commands and acknowledgements

POST `/api/commands` accepts exactly `id`, `action`, and optional `duration_seconds`. Actions are `refresh_status`, `suspend`, `enable`, `reprovision_admin`, and `reprovision_vpn`. Only suspend accepts a duration: omitted defaults to 3600 seconds; null means indefinite; an integer must be 900–86400. Each command targets one enrolled device. Reprovisioning requires the corresponding capability advertised during registration.

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","action":"suspend","duration_seconds":3600}
```

GET `/commands?id=UUID` returns signed pending envelopes and records the last VPN-only contact. POST `/command-results` accepts exactly:

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","request_id":"22334455-6677-8899-aabb-ccddeeff0011","result":"executed"}
```

`result` is `executed` or `failed`. Matching repeated acknowledgements are idempotent; unknown requests return 404 and conflicting results or epochs return 409. Acknowledgement receipt does not establish execution time. A provisioning acknowledgement means the snapshot was received and stored; CA trust may still require user approval before VPN profile application. See [remote-command semantics](REMOTE_COMMANDS.md).
