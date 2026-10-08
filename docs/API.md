> Device administrator setup and signed reprovisioning: [ADMINISTRATION.md](ADMINISTRATION.md).

> Version 0.3.0: authenticated POST status and command acknowledgements may be public; registration is restricted to 192.168.10.0/24; remaining REST routes stay VPN-only. See the repository `docs/REMOTE_COMMANDS.md` for complete setup instructions.

# HTTP API

All real-device endpoints require HTTPS. Registration is restricted to 192.168.10.0/24. Status and acknowledgements are authenticated public POST routes; remaining REST routes require the VPN subnets. If using a deployment prefix, registration and status must share the same prefix and origin. JSON bodies are limited to 2048 bytes; extra fields are rejected. Installation IDs are canonical lowercase UUIDs. Bearer credentials are case-sensitive. Do not place credentials in URL parameters.

| Route | Authentication | Success |
| --- | --- | --- |
| GET /health | None | 200 `{ "status": "ok" }` |
| POST /registrations | REGISTRATION_BEARER | 201 `{ "status_token": "device-specific credential" }` |
| POST /status | Device-specific status credential | 204, empty body |
| GET /api/devices | ADMIN_BEARER or admin browser session | 200 `{ "devices": [...] }` |
| POST /api/push | ADMIN_BEARER only | 202 `{ "result": "queued" }` |

Send `Authorization: Bearer <credential>` and `Content-Type: application/json` for JSON POST requests. Cookie authentication alone cannot trigger `/api/push`. Dashboard `/push` uses an administrator session and CSRF nonce instead.

## Enrollment

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","token":"abababababababababababababababababababababababababababababababab"}
```

The example token is synthetic. Actual tokens must be lowercase byte-pair hexadecimal, with variable length. Every successful registration rotates the installation's status credential. Store the returned credential in device-only Keychain; it cannot be retrieved later from the server. The updated native app requires the administrator provisioning protocol described in ADMINISTRATION.md; a legacy 204 response cannot provision it.

## Status

```json
{"id":"11223344-5566-7788-9900-aabbccddeeff","connection":"connected","policy_ok":true}
```

Connection values: `connected`, `connecting`, `reasserting`, `disconnecting`, `disconnected`, `invalid`. `policy_ok` must be a JSON Boolean, not a number/string. A credential for one installation cannot report for another. Report receipt time is assigned by the server. `policy_ok` describes local policy validation/recovery, not an audited traffic tunnel.

## Administrative device list

Each row includes `id`, `registered`, `seen`, `connection`, `policy_ok`, `pushed`, `push_result`, `registered_token`, `command_capable`, `administrator_capable`, and `tunnel_seen`. Timestamps are Unix seconds; fields without a result can be null. `policy_ok` and `registered_token` are SQLite-derived 0/1 values. Token and status hashes are excluded.

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
| 409 | Another dispatch is running |
| 413 | Body exceeds 2048 bytes |
| 429 | Dashboard login throttled: five failures per minute/address |
| 503 | APNs provider configuration absent |

Validation failures may precede authentication on `/status`; error bodies are not a stable API contract. Treat status codes as the contract and never assume all errors are JSON. `/health` is process liveness, not end-to-end readiness.

## VPN provisioning

Registration clients send `X-FamilyVPN-VPN-Protocol: 2`. Successful responses include `vpn` with `server`, `remoteIdentifier`, `trustedSSIDs` and UUID `revision`. The dashboard must have valid gateway settings first; otherwise registration returns 409 without rotating credentials. Configuration is managed through the authenticated, CSRF-protected dashboard. See [PROVISIONING.md](PROVISIONING.md).

`reprovision_vpn` commands include `vpn_digest`, a signed SHA-256 hash of a configuration snapshot. Authenticated `GET /vpn-configuration?id=UUID&request_id=UUID` returns the exact pending snapshot only for its device and enrollment epoch. Keep this route VPN-only. `vpn.caCertificate` is optional base64 DER, supplied through a validated PEM CA in the dashboard.
