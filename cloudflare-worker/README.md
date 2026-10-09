# Family VPN Cloudflare Worker

Cloudflare Worker proxy for the Family VPN push relay at `https://push.family-vpn.workers.dev`.

Place the Worker JavaScript in `src/index.js`. Deployment configuration will depend on the supplied code and its bindings. Store credentials using Cloudflare secrets; never commit tokens, APNs private keys or deployment credentials.

The dashboard relay protocol is documented in [push relay setup](../docs/PUSH_RELAY.md).
