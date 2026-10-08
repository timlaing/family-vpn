# Dashboard-managed device administrator password

Version 0.3.0 moves device administrator password creation and changes to the dashboard. This password protects local native administrator controls and is separate from Home Assistant login, ADMIN_BEARER and REGISTRATION_BEARER. A deployment uses one device administrator password. Existing devices keep their current verifier until registration or an acknowledged reprovision command succeeds.

## Setup and migration

1. Install the 0.3.0 service and updated native app. Back up the private service database and command signing key before updating.
2. Open the Home Assistant Ingress dashboard and set/confirm a password of at least 12 characters. The maximum is 1024 UTF-8 bytes; request bodies remain limited to 2 KiB.
3. On the device, open Dashboard registration, enter the HTTPS `/family-vpn/registrations` endpoint and enrollment secret, and authorize with device authentication. The proxy accepts registration exclusively from 192.168.10.0/24.
4. Registration retrieves the salted PBKDF2-SHA256 verifier (600,000 iterations, 32-byte salt/output), its revision and command trust. No plaintext administrator password is returned. First installation remains disabled until provisioned administrator configuration is available.
5. Install the VPN with its separate username/password. Use the dashboard-managed administrator password when unlocking local administrator controls.

Registration works before an APNs token exists, including macOS. The native request contains `{id, token:null}` with `X-FamilyVPN-Administrator-Protocol: 1` and `X-FamilyVPN-Command-Protocol: 1`. The response adds `administrator: {algorithm, iterations, salt, verifier, revision}`; binary fields are base64, revision is a UUID. Without dashboard setup, this protocol returns 409 before registering the device. Older clients remain registration-compatible but cannot install the updated app using a legacy 204 watchdog response. Legacy local verifiers continue protecting an installed VPN until replaced by authorized provisioning.

On iPhone/iPad, APNs tokens are registered afterward; unchanged tokens do not repeatedly rotate enrollment on every launch. macOS registers APNs tokens and receives signed commands in the app or running background helper, with VPN-only pending-command polling as a fallback. Failed manual enrollment restores the previous local enrollment records where possible; a server-side enrollment rotation may require another registration if the response was lost.

## Password changes and reprovisioning

Set a new password in the dashboard, then choose **Reprovision administrator password** on each updated, enrolled device. Alternatively, register the device again from the registration LAN. Changing the dashboard password alone does not prove devices have changed theirs. The command history must show an executed acknowledgement, or registration must succeed.

Administrator bearer POST `/api/commands` accepts `{"id":"device UUID","action":"reprovision_admin"}` with no duration. The server snapshots its current administrator verifier at queue time, signs it with the pinned service Ed25519 key and sends it as command data. The snapshot is included in protected pending-command retrieval and in APNs for registered iOS devices. It contains no plaintext password, but a verifier is sensitive credential material: keep service backups private and do not log command bodies. APNs transports the signed verifier to Apple; signatures authenticate data but do not encrypt it separately from transport protection.

The native client verifies signature, device, enrollment epoch, expiry and the administrator record format before writing its device-only Keychain verifier. The change does not alter VPN credentials, trusted networks or suspension. It also works for an enrolled iOS device before VPN installation. A newer administrator reprovision supersedes an older pending administrator reprovision; VPN policy and ping queues/replay counters are independent. Reprovision requests expire after 24 hours and retry at most every 15 minutes. Applying the same verifier preserves existing password retry delays. Applying a changed verifier resets old-password failures.

An executed acknowledgement means the local verifier update succeeded. Background delivery remains discretionary. Initial LAN registration is required to establish command trust; a command cannot bootstrap an unregistered device or replace a missing signing-key pin. Update and register older clients once before reprovision controls become available.

## Access boundaries

- Dashboard password setup: Home Assistant Ingress administrator access and CSRF, or authenticated standalone dashboard session and CSRF. It is unavailable on the add-on REST listener.
- Registration: 192.168.10.0/24 plus enrollment bearer authentication.
- Status and command acknowledgements: public HTTPS with device-scoped authentication and rate limits.
- Pending commands and administrator REST APIs: VPN subnets 10.20.30.0/24 and 10.20.40.0/24 plus their respective bearer credentials.

The service stores only the password verifier in its private SQLite database; it never echoes the password or verifier in dashboard HTML, logs or admin device/history APIs. Keep database backups protected because they include verifier material. No live Home Assistant/NPM configuration is changed by installing repository code; apply and verify the generated proxy locations and firewall restrictions separately.

## Gateway and Wi-Fi provisioning

Configure the VPN gateway, certificate identity and trusted Wi-Fi names in the dashboard before device registration. After changes, send Push VPN / Wi-Fi / CA to updated devices while the existing VPN is available, or re-register on the configured registration LAN. New CA trust requires approval in system Settings. The app stores deployment settings in Keychain; it no longer provides a developer gateway or editable local trusted Wi-Fi list. Subnet examples are illustrative and must be replaced with your own network ranges. See [provisioning](https://github.com/timlaing/family-vpn/blob/main/docs/PROVISIONING.md).
