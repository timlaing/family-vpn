# Apple device setup and use

Family VPN connects iPhone, iPad and Mac devices to infrastructure you operate. Configure a [VPN endpoint](VPN_ENDPOINT_SETUP.md) and the [Home Assistant dashboard](HOME_ASSISTANT.md) before registering devices. Install an app build supplied by your administrator; adding the Home Assistant repository installs the dashboard service only.

## Prepare the dashboard

1. Configure the APNs provider credentials and environment for the installed app build.
2. Set the device administrator password in the dashboard. This is separate from Home Assistant login and VPN credentials. See [administrator setup](ADMINISTRATION.md).
3. Set the VPN gateway, certificate identity, trusted Wi-Fi network names and optional public CA certificate. See [provisioning](PROVISIONING.md).
4. Configure the registration LAN and VPN-client access restrictions at your proxy. Documentation subnet ranges are examples; replace them with your own networks.

## Register and install the VPN

1. Connect the device to the permitted registration LAN.
2. Open the app's dashboard registration screen and enter the service URL and registration credential supplied by your administrator. Register the device to retrieve its provisioning settings and administrator verifier.
3. If your gateway requires the supplied CA, export the VPN CA profile from the app. Review and install it in system Settings. On iPhone/iPad, profiles appear under **General → VPN & Device Management**; manually installed roots may also require approval under **General → About → Certificate Trust Settings**. On Mac, approve the certificate/profile through system administration. Verify the certificate with your administrator before granting trust.
4. Use **Check certificate trust and apply provisioning** when certificate approval is required.
5. Enter your VPN username and password in the app, then approve the operating system's VPN installation request. VPN credentials remain local to the device.
6. Check connection status. Exact trusted Wi-Fi names configured by the dashboard allow the VPN to disconnect on those networks; an empty list keeps VPN policy enabled on every Wi-Fi network.

## Daily use and updates

The app shows connection and policy status. Administrator controls require the dashboard-managed device administrator password. On Mac, enable the background monitor through the app when required for monitoring while its window is closed.

The dashboard can request status, suspend or enable VPN policy, reprovision administrator access, and push new VPN/Wi-Fi/CA settings. See [remote commands](REMOTE_COMMANDS.md). APNs delivery and background execution are best effort; check device acknowledgements instead of assuming a sent command executed.

Allow notifications to receive CA-update alerts and badges. A new CA requires system trust approval; the app cannot grant it silently. Keep the old VPN gateway available until devices retrieve a pushed replacement configuration. Re-register on the registration LAN if a disconnected device cannot retrieve an update.

Personal VPN on an unsupervised device provides best-effort protection. Users can remove profiles or disable system permissions. For the administrator password and recovery process, see [administration](ADMINISTRATION.md); for certificate rotation, see [certificate setup](VPN_CERTIFICATES.md).
