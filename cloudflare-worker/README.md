# Family VPN Cloudflare Worker

POST-only proxy at `https://push.family-vpn.workers.dev` for the primary relay hosted inside the Family VPN Home Assistant app. The upstream app handles APNs, endpoint registration, rotation, replay protection, expiry, rate limits and signed owner callbacks. The Worker stores no endpoint or device records.

## Worker settings

Keep these values in Cloudflare Worker settings, outside the repository:

| Setting | Type | Value |
| --- | --- | --- |
| `UPSTREAM_URL` | Environment variable | Primary HA app's public HTTPS REST base, including its prefix if any |
| `RELAY_PROXY_TOKEN` | Secret environment variable | Random private credential matching the app's hosted-relay operator setting |

The Worker accepts only POST `/endpoints`, `/rotate` and `/push`. It appends these paths to the configured upstream base and preserves query, exact body bytes and endpoint authentication headers. It replaces a caller-supplied `X-Relay-Proxy-Token` with its private secret. Missing configuration fails closed. The credential is not returned to callers, removed from response headers, and never logged. Network errors use generic messages.

Responses preserve upstream status/body; redirects are returned without following them. GET `/health` returns 405 at the Worker; check the HA app's health route directly. The upstream REST locations must expose the hosted relay routes (`--host-relay` in the proxy generator) and preserve HMAC headers. Owner callbacks go directly from the HA relay to the owner's REST base.

## Deployment and verification

Use `cloudflare-worker` as the repository root directory and `src/index.js` as the entrypoint. With Wrangler installed and authenticated to the correct account:

```sh
wrangler deploy
```

The Worker name is `push`; the account's Workers subdomain must be `family-vpn` for the published address. `keep_vars = true` preserves dashboard-managed variables. Configure the secret through Cloudflare's dashboard or `wrangler secret put RELAY_PROXY_TOKEN`. Do not put the secret in Wrangler `vars`. See [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) and [secret bindings](https://developers.cloudflare.com/workers/configuration/secrets/).

For local development, supply both variables in a private `.dev.vars` file and run `wrangler dev`. Offline tests mock forwarding:

```sh
npm test
```

These tests do not establish the deployed Worker, upstream availability or physical-device delivery. After deploying, configure the primary HA relay and register a dashboard as described in [push relay setup](../docs/PUSH_RELAY.md).
