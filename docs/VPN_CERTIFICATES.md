# VPN certificates

Use this guide for a new private CA deployment on [RouterOS](MIKROTIK_IKEV2.md) or [strongSwan](STRONGSWAN_IKEV2.md). A publicly trusted server certificate is an alternative; in that case leave the dashboard CA field empty and install the complete issuer chain on the endpoint.

The examples create a proper CA and a separate server leaf. Run them in a private directory on a trusted administration machine, outside the repository. Keep the CA private key offline; only the leaf's private key goes to the endpoint. Use a current OpenSSL release. Commands that need a CA key passphrase prompt for it; do not put it in shell history.

## Create a private CA

```sh
umask 077
mkdir family-vpn-certificates
cd family-vpn-certificates
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -aes-256-cbc -out vpn-ca-key.pem
openssl req -new -x509 -sha256 -days 3650 -key vpn-ca-key.pem -out vpn-ca.pem -subj '/CN=Family VPN Root CA' -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' -addext 'keyUsage=critical,keyCertSign,cRLSign' -addext 'subjectKeyIdentifier=hash'
```

The CA may sign leaf certificates directly; `pathlen:0` excludes subordinate CAs. Use a separate PKI design if you need intermediate authorities.

## Issue the server certificate

Substitute your gateway name consistently. If the dashboard uses a different server certificate identity, include that DNS SAN too. For an IP endpoint, supply an `IP:` SAN with the actual address.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out vpn-server-key.pem
openssl req -new -sha256 -key vpn-server-key.pem -out vpn-server.csr -subj '/CN=vpn.example.org'
```

Create `vpn-server.ext`:

```ini
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:vpn.example.org
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
```

Sign and verify:

```sh
openssl x509 -req -sha256 -days 365 -in vpn-server.csr -CA vpn-ca.pem -CAkey vpn-ca-key.pem -CAcreateserial -extfile vpn-server.ext -out vpn-server.pem
openssl verify -CAfile vpn-ca.pem -purpose sslserver -verify_hostname vpn.example.org vpn-server.pem
openssl x509 -in vpn-ca.pem -noout -text
openssl x509 -in vpn-server.pem -noout -ext subjectAltName
openssl x509 -in vpn-ca.pem -noout -fingerprint -sha256
```

Verify `CA:TRUE` on the root, `CA:FALSE` on the leaf, the expected SAN, expiry and SHA-256 root fingerprint. The server key example is unencrypted for unattended startup and must remain root-only; use encrypted-key loading if your deployment supports a secure startup passphrase mechanism.

## Install on the endpoint

For strongSwan, install `vpn-server.pem` under `/etc/swanctl/x509/`, `vpn-server-key.pem` under `/etc/swanctl/private/` (mode `0600`), and `vpn-ca.pem` under `/etc/swanctl/x509ca/`. `swanctl --load-creds` loads an unencrypted key automatically. If using an encrypted key, provide its passphrase interactively or through a protected `secrets.private-*` section as described in the gateway guide.

For RouterOS, create an encrypted PKCS#12 package for local import; the command prompts for an export password:

```sh
openssl pkcs12 -export -name vpn-server -inkey vpn-server-key.pem -in vpn-server.pem -certfile vpn-ca.pem -out vpn-server.p12
```

Transfer it securely to the router and import through System → Certificates. Verify the imported server leaf has its private key and select its actual RouterOS name in the IPsec identity. Trust the intended CA. Remove the transferred PKCS#12 file after a successful import; keep a secure recovery copy separately. Do not install the CA signing key on the router.

## Provision devices and rotate

Paste **only `vpn-ca.pem`** into dashboard VPN provisioning. Neither `vpn-server-key.pem`, `vpn-ca-key.pem`, nor `vpn-server.p12` belongs there. The leaf is not a CA. The dashboard validates a single PEM certificate with an explicit CA basic constraint and delivers its public DER certificate at registration or through a signed provisioning update.

Confirm the root fingerprint out of band before granting trust. On a device, export the supplied CA profile from the app, install it through system Settings and approve the appropriate certificate trust. [Apple describes manual certificate trust](https://support.apple.com/en-gb/102390); the app cannot grant it automatically.

For a CA change, stage the new certificate while the old VPN and dashboard retrieval path still work. Obtain device receipt, notify the user, approve new trust and verify policy/tunnel state before retiring the old endpoint/CA. The dashboard currently provisions one CA at a time; use a separate replacement endpoint or a planned maintenance window when your server cannot offer an overlap. Existing system trust for an old CA is not automatically removed by replacing the app's provisioned certificate. Remove obsolete trust through Settings or device management after migration.
