# Start with the published Family VPN app

You operate your own VPN endpoint and Home Assistant dashboard. The primary relay provides Apple push delivery; you do not need Apple developer credentials, a custom build, or your own Worker.

## Before you begin

- Home Assistant with Supervisor and the Family VPN app installed.
- A working IKEv2/EAP-MSCHAPv2 VPN gateway and a VPN account for each device. For a new Linux gateway, use the [strongSwan Docker/Compose package](../strongswan-endpoint/README.md); existing gateways can follow the [endpoint guides](VPN_ENDPOINT_SETUP.md).
- A public HTTPS dashboard address and reverse proxy able to enforce separate enrollment-LAN and VPN-client access rules. The authenticated reporting and callback routes are public; other REST access remains restricted.
- The published Family VPN native app with the new setup-link support. Older builds require the manual registration form.

## Dashboard setup

1. Install and start the HA app, then **Open Web UI**. Home Assistant handles dashboard sign-in.
2. The **Setup guide** opens automatically until the required setup is complete. Enter your public REST base address and VPN gateway. Optionally add trusted Wi-Fi and upload a private CA certificate. Leave Advanced server identity blank when it matches the gateway.
3. Set and confirm the device administrator password. It protects native VPN controls and is separate from VPN account credentials.
4. On **Check setup**, expand **Generate Nginx Proxy Manager configuration**. Enter your reachable HA host address, REST port (8500), enrollment LAN CIDRs and VPN client CIDRs. Copy the generated complete locations into the proxy server configuration, validate and reload Nginx. Never nest them inside another location.
5. Select **Check setup and enable notifications**. The dashboard verifies HTTPS reaches this installation and registers your VPN endpoint with the primary relay. No Apple credentials or relay secrets are required from you. Existing endpoint registrations cannot be overwritten; an existing owner can recover with its current key through Advanced.
6. Open **Add device**, connect that device to the enrollment LAN, and generate a device setup code.

The connection check establishes HTTPS/routing reachability, not VPN operation or correct enforcement of your network ACLs. Verify that registration fails from outside the enrollment LAN and VPN-only routes fail outside the VPN client network before enrolling real devices. The primary relay must be operational and able to reach the public callback; a locally successful test does not prove the deployed relay is available.

## Device setup

1. Open Family VPN and choose **Scan setup code** on iPhone/iPad, or paste the generated setup link. On macOS, open the setup link or paste it into the app.
2. Confirm that the displayed dashboard hostname is yours, then authenticate on the device.
3. Registration retrieves gateway, trusted Wi-Fi, administrator settings and the optional CA. The invitation expires after ten minutes, works once and is replaced by a device-scoped credential stored in Keychain. Generating another code invalidates the previous unused invitation. If the first response is lost after redemption, generate a new code and try again.
4. Enter the device's VPN username/password. Approve VPN installation and notification prompts. If a private CA was supplied, install its profile and approve trust in system Settings as directed by the app.
5. Test on cellular or untrusted Wi-Fi and verify the connected indicator and dashboard report. On trusted Wi-Fi the VPN disconnects by policy.

Automatic policy checks default to on and begin once a device has registered with an APNs push token and push delivery is ready. Apple push delivery remains best effort. Existing saved on/off settings are retained during an upgrade.

Keep setup links private and do not paste them into public support reports. They contain a temporary enrollment credential, not the dashboard's reusable enrollment bearer. The dashboard stores only invitation hashes; device enrollment credentials are scoped to one installation ID. A copied unexpired invitation can still be redeemed by someone on the allowed enrollment network, so create it only when you are ready to register.

## Advanced deployments

The menu's Advanced/Push setup pages provide **Direct APNs** and optional relay hosting. These are separate operator features; normal users of the published app use Primary relay. See [push setup](PUSH_RELAY.md), [proxy/network configuration](HOME_ASSISTANT.md), and [native provisioning](PROVISIONING.md).
