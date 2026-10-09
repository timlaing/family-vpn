# Push relay setup

The published Apple app needs pushes sent with its publisher’s APNs credentials. Your own Apple keys work with a custom app built and signed for your Apple developer account. Choose the transport in the dashboard’s **Advanced** page. A fresh Home Assistant installation defaults to relay mode; existing saved APNs configurations retain direct mode.

The default relay URL is `https://push.family-vpn.workers.dev` and remains configurable. This repository supplies the service; it does not deploy or provide a running hosted endpoint automatically.

## Dashboard setup

1. Complete VPN provisioning and administrator setup. The configured VPN gateway becomes the relay endpoint identifier (DNS names are case-insensitive; IP addresses are normalized).
2. Publish the dashboard REST interface through trusted HTTPS. Allow public **POST** requests to `/family-vpn/relay-results`, alongside public device status and command acknowledgements. Keep registration LAN-only and other REST routes VPN-only. Generate the locations with `Tools/generate_npm_location.py --public-reports` and your deployment’s network options.
3. Open **Advanced**, choose **Published app relay**, and use the default `https://push.family-vpn.workers.dev` or enter another relay HTTPS origin. Host the relay at the origin root, without a URL prefix. Enter the dashboard callback URL, for example `https://dashboard.example.org/family-vpn/relay-results`.
4. Enter the enrollment credential supplied privately by the relay operator. The separate endpoint signing token is generated on first startup if left blank. You can supply a 32–256 character printable ASCII token instead; neither credential belongs in the native app or a public configuration file.
5. Leave the endpoint limit at **10 requests per minute**, or choose 1–100 within the operator’s cap. Save, then select **Register / update relay endpoint**. Registration verifies a signed callback to your dashboard before retaining the endpoint.
6. Confirm the registered state, then test a manual status refresh on an enrolled physical device. Enable automatic policy checks only after confirming push delivery, the device acknowledgement and a fresh status report.

The endpoint token and enrollment credential persist privately in `/data/relay-token` and `/data/relay-enrollment`. Blank credential inputs retain the stored values. Protect Home Assistant backups. Changing the relay address, callback, rate or VPN gateway requires registration again. Replacing an already registered endpoint token requires operator coordination: an existing server registration cannot be taken over with another token. Resetting push defaults preserves relay registration and credentials.

## Relay operator deployment

Run the relay separately from the Home Assistant dashboard. It retains endpoint registrations and short-lived request/rate-limit records in SQLite; mount persistent storage. The publisher’s APNs key stays on this service, never in users’ Home Assistant apps.

Build the root container:

```sh
docker build -t family-vpn-relay .
```

Create a private environment file (mode `0600`) with these variables. Generate separate random secrets of at least 32 characters using a local secret manager or `openssl rand -hex 32`. Do not commit the file or the `.p8` key.

```dotenv
APNS_KEY_FILE=/keys/apns.p8
APNS_KEY_ID=YOUR_KEY_ID
APNS_TEAM_ID=YOUR_TEAM_ID
APNS_TOPIC=YOUR_PUBLISHED_APP_BUNDLE_ID
APNS_ENVIRONMENT=production
RELAY_ENROLLMENT_BEARER=YOUR_RANDOM_ENROLLMENT_SECRET
RELAY_STORAGE_SECRET=YOUR_SEPARATE_RANDOM_STORAGE_SECRET
RELAY_DATABASE=/data/relay.sqlite
RELAY_MAX_PER_MINUTE=100
```

Use the published app’s actual bundle identifier and Apple team; production applies to TestFlight and App Store builds. Sandbox applies to development builds.

Prepare the mounted data/key directories so container UID/GID `10001:10001` can write `/data` and read `/keys/apns.p8`. Run one service instance against this database:

```sh
docker run -d --name family-vpn-relay \
  --env-file /secure/relay.env \
  -p 127.0.0.1:8501:8500 \
  -v /srv/family-vpn-relay/data:/data \
  -v /secure/relay-keys:/keys:ro \
  family-vpn-relay \
  gunicorn --workers 1 --threads 4 --bind 0.0.0.0:8500 \
  --access-logfile /dev/null --error-logfile - family_vpn.relay_wsgi:application
```

Terminate HTTPS at a reverse proxy, forwarding `/endpoints`, `/push` and `/health` unchanged. Permit only required methods; retain the `X-Relay-*` headers. Disable body logging, tracing of payloads and debugging. Outbound access must reach APNs over HTTP/2 and public HTTPS dashboard callbacks. Callback addresses resolving to private, loopback or other non-public networks are rejected, including mixed public/private DNS answers. TLS uses the callback hostname while connecting to the validated address.

Back up the endpoint database and protect the storage secret separately. Losing or replacing the storage secret makes existing encrypted endpoint credentials unreadable. Stop the service before a file-copy backup. SQLite is suitable for this single-host service; deploying to Lambda would require adapting persistence to a shared service such as DynamoDB. This implementation does not include that adapter.

Distribute the enrollment credential privately to approved owners. It authorizes new endpoint registrations; it is not the per-endpoint signing key. Use a proxy-level enrollment throttle in addition to the application’s endpoint limits. Remove an endpoint only through controlled operator maintenance of the database while the service is stopped; there is no public deletion or token-reset API.

## Authentication and data flow

| Route | Authentication | Purpose |
| --- | --- | --- |
| Relay `POST /endpoints` | Enrollment bearer; updates also require existing endpoint HMAC | Register VPN server, callback, token and limit; prove callback ownership |
| Relay `POST /push` | Endpoint HMAC | Forward the transient device token and signed command to APNs |
| Dashboard `POST /relay-results` | Endpoint HMAC | Receive registration challenges and push acceptance/error results |
| Relay `GET /health` | None | Generic liveness only |

HMAC-SHA256 covers the HTTP method, exact URL path, Unix timestamp, UUID nonce and SHA256 digest of the exact JSON body, separated by newlines. `X-Relay-Time`, `X-Relay-Nonce` and `X-Relay-Signature` carry these fields. Requests older/newer than five minutes and repeated nonces are rejected. Nonces are retained for ten minutes to cover the full validity window of future-dated requests. Keep clocks synchronized. A callback signs the external path, including any proxy prefix; the dashboard verifies against its configured callback URL.

Requests are limited by canonical VPN gateway, across endpoint updates and pushes, in a rolling minute. Replay/rate records persist across restarts. A rejected request returns HTTP 429; the dashboard records `retry_later`. Initial registration uses the enrollment gate and callback challenge. An endpoint’s first registration establishes ownership; the service does not independently prove ownership of the VPN hostname. The operator should verify it when issuing enrollment access. Separate owners sharing one VPN gateway must share one coordinated endpoint registration.

The relay stores no device table, push tokens, command payloads or status history. It processes device identifiers, push tokens and commands transiently. Push results return both in the synchronous response and a signed callback to the owner dashboard; callback failure does not undo an APNs submission. The dashboard remains responsible for device credentials, commands, status and acknowledgements. The relay does not queue or retry payloads. APNs acceptance is not proof of delivery or execution; silent pushes remain best effort.
