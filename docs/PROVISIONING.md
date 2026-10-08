# Dashboard VPN provisioning

Set the VPN gateway hostname or IP address, server certificate identity, and trusted Wi-Fi SSIDs in the authenticated dashboard before registering devices. The certificate identity defaults to the gateway. SSIDs are exact, case-sensitive names; an empty list keeps VPN enforcement enabled on every Wi-Fi network.

Updated apps request `X-FamilyVPN-VPN-Protocol: 1` during authenticated LAN registration. The response includes `vpn.server`, `vpn.remoteIdentifier`, `vpn.trustedSSIDs`, and a UUID `vpn.revision`. Missing configuration returns HTTP 409 before credentials rotate. The app validates and stores these settings in Keychain and applies the Wi-Fi policy when provisioning changes, including after restart. VPN credentials remain local to the device.

After changing gateway or Wi-Fi settings, re-register each device on your configured registration network. Administrator password reprovisioning is a separate command and does not update VPN settings. Installation or profile changes may require operating-system approval. For private certificate authorities, install and trust your own CA through the operating system; the application no longer assumes the developer's gateway or CA.

All subnet ranges in documentation and proxy examples are illustrative. Replace them with your registration LAN and VPN client subnets. Enforce these access restrictions at your reverse proxy; the application does not infer trusted source networks from example addresses. Public status and acknowledgement routes still require device credentials.
