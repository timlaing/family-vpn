# Family VPN Cloudflare Worker

POST-only reverse proxy at `https://push.family-vpn.workers.dev`. It forwards requests to the separately hosted Family VPN relay. The upstream handles APNs, endpoint registration, HMAC authentication, replay protection, per-endpoint limits and signed callbacks. The Worker does not implement those functions or store device records.

## Configuration and deployment

Set the Worker's `UPSTREAM_URL` environment variable to the HTTPS origin hosting the relay, for example `https://relay.example.org`. A value is not committed because the upstream address is deployment-specific. Configure it in Cloudflare's Worker settings before accepting requests. Keep APNs keys and endpoint secrets on the upstream relay, rather than in Worker source or variables.

The proxy replaces any path/query in `UPSTREAM_URL` with the incoming request's path/query. The upstream must therefore serve `/endpoints` and `/push` at its origin root. Request headers (including enrollment bearer and `X-Relay-*` signatures), body bytes, upstream status and response are forwarded. Redirects are returned without following them; avoid redirecting these signed routes. All non-POST requests, including GET `/health`, return 405 at the Worker. Check upstream health directly.

From this folder, with Wrangler installed and authenticated to the correct Cloudflare account:

```sh
wrangler deploy
```

The configured Worker name is `push`. The `push.family-vpn.workers.dev` address requires the account's Workers subdomain to be `family-vpn`. `keep_vars = true` preserves dashboard-configured variables on deployment. See [Wrangler configuration](https://developers.cloudflare.com/workers/wrangler/configuration/) and [environment variables](https://developers.cloudflare.com/workers/configuration/environment-variables/).

For local development, put `UPSTREAM_URL=https://YOUR_RELAY_ORIGIN` in a private `.dev.vars` file, then run `wrangler dev`. For offline forwarding tests using Node's built-in test runner:

```sh
npm test
```

Local tests mock the outbound network call; they do not verify the deployed Worker, APNs delivery or upstream availability. The supplied Worker logs upstream fetch errors; do not enable request-body logging or log credentials. The relay sends signed results directly to each registered dashboard callback, independently of this proxy.

See [push relay setup](../docs/PUSH_RELAY.md) for the upstream service and dashboard configuration.
