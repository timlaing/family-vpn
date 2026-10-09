# Push delivery and hosted relay

Family VPN supports two dashboard choices:

- **Primary**: use the published app and `https://push.family-vpn.workers.dev`. The Worker forwards requests to the publisher’s Home Assistant app, which sends them to APNs.
- **Custom**: send directly to Apple APNs using credentials for your own custom app. Custom relay URLs are not supported by the dashboard configuration.

The same Home Assistant app can host the primary relay and use it for its own enrolled devices. The relay holds endpoint registrations and short-lived request/rate-limit records, with no device table, push-token retention or command-payload queue. Device status and execution acknowledgements go directly to each owner’s dashboard.

## Dashboard setup

1. Open VPN provisioning and enter your VPN gateway, trusted Wi-Fi and optional public CA. Set the **Public REST interface address** once, for example `https://dashboard.example.org/family-vpn`, without `/registrations`. Enrollment, reports and the relay callback use this base; no separate callback setting is needed.
2. Complete the device administrator password setup.
3. The next page is **Push setup**. Select **Primary** or **Custom**.
4. For Primary, select Continue and then **Register endpoint**. The dashboard generates and sends its VPN endpoint signing key to the relay through the Worker. Owners do not need the publisher’s APNs key or the private Worker credential.
5. For Custom, Continue opens Advanced. Upload your APNs credential file, enter the custom app’s **Bundle ID**, and choose **Push URL**: production (`https://api.push.apple.com`) or development (`https://api.sandbox.push.apple.com`). Save returns to Push setup. Finish registration to continue to Status & reports. This records local setup; no endpoint is registered with the primary relay in Custom mode.
6. Enroll the native app from your permitted registration network, then send a manual **Refresh status**. Confirm APNs acceptance, a device execution acknowledgement and a new report before enabling automatic checks in Administration.

Advanced hides client provider settings for Primary. Its only key action is **Force rotate key**, alongside registration/rotation status. Custom displays only the credential upload, bundle ID and push URL. A separate collapsed operator section configures hosting on the publisher’s installation. Uploaded key contents and saved Worker/endpoint credentials are never returned in page HTML.

Protect the app’s `/data` and backups. They include its SQLite databases, endpoint keys and APNs credentials. Existing callback settings migrate to the single REST address. Existing saved direct APNs settings remain Custom; new installations default to Primary.

## APNs credential upload

Apple token authentication requires the private `.p8` key, Key ID and Apple Team ID. To keep the visible form to three inputs, upload a private JSON file containing:

```json
{
  "key_id": "YOUR_10_CHARACTER_KEY_ID",
  "team_id": "YOUR_10_CHARACTER_TEAM_ID",
  "private_key": "YOUR_P8_PEM_CONTENT_WITH_ESCAPED_NEWLINES"
}
```

Use the exact downloaded PEM contents, including its delimiters. Construct the file locally with a JSON-aware editor or script; do not commit it. The app validates a P-256 private key and writes it atomically with file mode `0600`. The upload limit is 16 KB. Leaving the upload empty retains the saved credential. For Custom, an original `AuthKey_<KeyID>.p8` file also works when its Team ID is already configured from an earlier credential upload. The first upload should use JSON.

Create an APNs-enabled key under the Apple team that signs your app. For a topic-specific key, select the app’s bundle ID and the correct environment. TestFlight/App Store use production; Xcode development builds use sandbox. The current published Family VPN topic is `uk.co.laingcorp.myvpn`.

The `.p8` signing key does not expire. APNs JWT authentication tokens do: the app caches a token and refreshes it after 50 minutes on the next push. No annual certificate renewal is needed for this authentication mode. To replace a revoked or compromised provider key, create its replacement in Apple Developer, upload the new credential in the app, verify delivery and then revoke the old key. This is independent of the dashboard endpoint-key rotation below. See [Apple key setup](https://developer.apple.com/help/account/keys/create-a-private-key/) and [APNs token authentication](https://developer.apple.com/help/account/capabilities/communicate-with-apns-using-authentication-tokens/).

## Hosting the primary relay on Home Assistant

1. Update the Family VPN app and complete its normal dashboard setup.
2. Open **Advanced → Host the primary push relay on this app**.
3. Upload the publisher’s APNs JSON credential, set the published app bundle ID, and choose the Apple push URL.
4. Generate a separate random Worker credential of at least 32 characters. Enter it into the blank password field in this operator section. It is stored privately; leaving the field blank retains it. An externally configured `RELAY_PROXY_TOKEN` environment variable can also supply this credential. Do not include it in the repo.
5. Set **Maximum requests per endpoint per minute** (default 10; configurable 1–100), enable the hosted relay and save.
6. Publish this same app’s REST base through Nginx Proxy Manager. Generate the complete locations with `--host-relay` in addition to `--public-reports` and your LAN/VPN boundaries. The relay API routes are POST `/endpoints`, `/rotate` and `/push`. Each hosted request requires the private Worker credential; rotation and push additionally require the endpoint HMAC. Ingress forms are never exposed on this listener.
7. On the Cloudflare Worker, keep `UPSTREAM_URL` in Worker settings, pointing at this REST base. A path prefix is supported, for example `https://dashboard.example.org/family-vpn`.
8. Add **`RELAY_PROXY_TOKEN` as a Cloudflare secret environment variable**, matching the value entered in the app. The Worker inserts it into `X-Relay-Proxy-Token`, replacing any client-supplied header. It is never offered through a token-download endpoint or returned in response headers. The updated Worker fails closed if either setting is absent.
9. Deploy the updated Worker, then register an owner dashboard through Push setup. The relay must be able to reach public HTTPS dashboard callbacks and Apple APNs over HTTP/2.

The operator’s app uses its existing persistent `/data` volume; no separate Python relay container is required. A legacy standalone relay entrypoint remains available for existing operators, but it uses its explicitly configured enrollment bearer rather than the hosted Worker gate. Use the integrated Home Assistant service for this setup.

Example proxy generation with generic networks:

```sh
python3 Tools/generate_npm_location.py \
  --upstream 192.168.10.20 --allow 10.20.30.0/24 \
  --registration-allow 192.168.10.0/24 \
  --public-reports --host-relay
```

Apply and validate the generated server-level locations in your NPM deployment. Owner dashboards need `--public-reports`; only the primary hosting installation needs `--host-relay`. Callback URLs resolving to private/loopback or mixed public/private addresses are rejected. Use public HTTPS with trusted certificates, and preserve the forwarded signature headers.

## Endpoint lifecycle

- Registration uses a canonical VPN server address. An existing endpoint always returns HTTP 409, even if the supplied key matches. It cannot be overwritten through registration.
- New endpoints have a 30-day initial grace period. A valid authenticated push attempt refreshes the last-push time, including a provider error; registration and rotation do not. Endpoints with no push attempt for 30 days are removed, including their replay records. HA maintenance checks every minute and API access also prunes expired records.
- Endpoint signing keys rotate automatically when 24 hours old while the dashboard is running and can contact the relay. Rotation is also checked before pushing. An unreachable dashboard/relay cannot complete rotation; stale keys cannot push until authenticated rotation succeeds. **Force rotate key** performs the same authenticated operation immediately.
- Rotation requires an HMAC made with the current endpoint key. The old key stops working when the new one is installed. A privately persisted pending key allows recovery after a lost response: the client first proves possession of the pending key, then uses the old key if the relay has not yet accepted the change.
- If an endpoint expires, rotation returns missing, clears the dashboard’s registered state and allows registration again. Losing the current endpoint key requires waiting for expiry or controlled operator maintenance; registration cannot recover or take over it.

HMAC-SHA256 covers method, exact API path, timestamp, UUID nonce and SHA256 of the exact body. Time skew is limited to five minutes; nonces remain for ten minutes. Keep clocks synchronized. Rotation requests and pushes share the endpoint’s rolling-minute quota (default 10). APNs acceptance does not prove delivery or execution; background pushes are best effort.
