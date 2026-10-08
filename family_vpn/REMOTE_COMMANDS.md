# Remote commands and network boundaries

Version 0.3.0 supports **refresh status / ping**, **suspend**, and **enable / unsuspend**, and **reprovision administrator password** for enrolled iPhone, iPad and Mac devices. Re-enroll the updated native app from the registration LAN (192.168.10.0/24) to authorize commands. macOS can enroll before an APNs token is available, then registers its token and receives signed APNs commands in the app or running background helper. VPN-connected pending-command polling remains a fallback on every platform.

The dashboard offers 15-minute, one-hour, four-hour, 24-hour or indefinite suspension. Enable clears suspension and restores On Demand rules; trusted Wi-Fi rules still apply. APNs acceptance is not execution or guaranteed delivery. Requests remain pending until the device acknowledges execution or failure. Control requests expire after 24 hours; refresh requests after one hour; timed suspensions cannot execute after their end time. Retries are limited to once per 15 minutes. A newer control request supersedes an older pending control request.

The device verifies an Ed25519 signature, enrollment epoch, device identifier, expiry and persistent sequence before changing policy. Enrollment pins the service public key and authorizes these four remote actions without entering the local administrator password each time. Re-enrollment rotates the device credential and epoch, revoking old requests. Back up the private `command-signing.key` alongside the database, keep it private, and re-enroll devices if it is replaced. Never commit this key.

## Public reporting

Only POST `/family-vpn/status` and POST `/family-vpn/command-results` are publicly proxied. Both require the enrolled device's scoped bearer credential over HTTPS. Registration is restricted exclusively to 192.168.10.0/24 and retains enrollment bearer authentication. Pending-command fetches, administrator APIs and remaining REST routes are restricted to VPN source subnets 10.20.30.0/24 and 10.20.40.0/24. The dashboard/configuration remains Home Assistant Ingress only. Prevent direct Internet access to the add-on port 8081.

Reports are limited across both routes to 20 requests per credential per minute and 120 per socket peer per minute; behind NPM the peer is shared. Limits reset after restart. Public reported connectivity is a device assertion, not independent proof of VPN connectivity. The dashboard's last VPN-only contact is recorded only by authenticated pending-command fetches through the protected route. Its meaning depends on correctly applied proxy ACLs and firewall rules.

Generate the complete Nginx locations with:

```sh
python3 Tools/generate_npm_location.py --upstream 192.168.1.20 --allow 10.20.30.0/24 --allow 10.20.40.0/24 --public-reports --registration-allow 192.168.10.0/24
```

Do not nest complete locations inside an NPM custom-location Advanced box. Apply them where complete server location definitions are supported, verify Nginx syntax, and test from outside and inside the VPN. Preserve Authorization headers and ensure NPM sees the VPN source addresses rather than a NAT gateway. The intended public base URL is https://ha.example.org/family-vpn/. No live proxy deployment has been performed.

## REST commands

Administrator bearer POST `/api/commands`: `{"id":"device UUID","action":"refresh_status|suspend|enable|reprovision_admin"}`. For suspend, optional `duration_seconds` defaults to 3600; use null for indefinite or an integer 900–86400. Returns 202 with request_id; APNs must be configured. GET `/api/commands` returns sanitized history.

Device bearer GET `/commands?id=device UUID` returns at most three signed pending envelopes and records protected contact. Device bearer POST `/command-results` accepts exactly `{"id":"device UUID","request_id":"request UUID","result":"executed|failed"}`. Success returns 204; unknown request 404; conflicting result/epoch 409. Idempotent acknowledgements are accepted. Late acknowledgements can resolve an expired request if it executed before expiry. Acknowledgement receipt time does not establish execution time.

The native client retains up to 32 acknowledgement receipts and flushes two per recovery pass, including while disconnected. Recovery and APNs execution remain subject to iOS scheduling. Test real APNs and IKEv2 on physical hardware; simulator and synthetic proxy tests do not establish delivery or tunnel behavior.

Administrator setup, migration and reprovisioning are documented in [ADMINISTRATION.md](ADMINISTRATION.md). Reprovision commands snapshot the verifier at queue time and require an updated administrator-capable registration. Their replay tracking and supersession are independent of VPN policy and refresh requests.
