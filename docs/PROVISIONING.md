# Dashboard VPN provisioning

Set the VPN gateway hostname or IP address, server certificate identity, and trusted Wi-Fi SSIDs in the authenticated dashboard before registering devices. The certificate identity defaults to the gateway. SSIDs are exact, case-sensitive names; an empty list keeps VPN enforcement enabled on every Wi-Fi network.

Updated apps request `X-FamilyVPN-VPN-Protocol: 2` during authenticated LAN registration. The response includes `vpn.server`, `vpn.remoteIdentifier`, `vpn.trustedSSIDs`, a UUID `vpn.revision`, and optional base64 DER `vpn.caCertificate`. Missing configuration returns HTTP 409 before credentials rotate. The app validates and stores these settings in Keychain and applies the Wi-Fi policy when provisioning changes, including after restart. VPN credentials remain local to the device.

## Push updates

Save the desired gateway, certificate identity, trusted Wi-Fi list and optional single PEM CA certificate in the dashboard. Then choose **Push VPN / Wi-Fi / CA** for an updated, registered device. `reprovision_vpn` snapshots the complete configuration at queue time; later dashboard edits cannot change that command. The signed APNs envelope contains a SHA-256 digest rather than the large certificate payload. Devices fetch `GET /vpn-configuration?id=…&request_id=…` using their reporting credential and verify that digest. The route remains VPN-only under the existing reverse-proxy ACL. Only public status and acknowledgement routes should bypass that ACL.

Keep the old gateway available until devices retrieve updates: disconnected devices cannot fetch the snapshot through the VPN-only route. Failed retrieval remains pending for retry until command expiry (24 hours). Re-registration on the registration LAN is the recovery path. Provisioning replay counters are independent of suspend/enable and administrator-password commands. Old app versions must update and re-register to advertise protocol 2 support.

A pushed CA update displays a local notification and application badge, subject to notification permission. The app provides **Export VPN CA profile** on its main page, including for installed VPNs. Install the profile and approve certificate trust in system Settings, then use **Check certificate trust and apply provisioning**. The application cannot silently grant system trust. The badge clears after a successful trust check. Existing system VPN settings remain in place while a new CA requires approval. A command acknowledgement confirms that the settings were received and stored; a subsequent successful policy report confirms profile application. CA removal is also supported by saving an empty CA field and pushing the resulting configuration.

Administrator password reprovisioning is a separate command. Installation or profile changes may require operating-system approval. VPN usernames and passwords remain local. Supplied CA profiles contain only the public certificate, never private keys or VPN credentials.

All subnet ranges in documentation and proxy examples are illustrative. Replace them with your registration LAN and VPN client subnets. Enforce these access restrictions at your reverse proxy; the application does not infer trusted source networks from example addresses. Public status and acknowledgement routes still require device credentials.

## VPN endpoint setup

See the [endpoint setup guide](https://github.com/timlaing/family-vpn/blob/main/docs/VPN_ENDPOINT_SETUP.md), with MikroTik RouterOS and strongSwan settings based on the inspected IKEv2/EAP deployment. Configure your gateway and authentication backend before enrolling devices.
