"""Import a sanitized XML/binary or signed CMS EAP IKEv2 profile."""
import argparse
import json
import plistlib
import subprocess
import uuid
from pathlib import Path

SECRETS = {"AuthName", "AuthPassword", "SharedSecret", "Password", "PayloadCertificateUUID", "VPNSubType"}
SUPPORTED = {"RemoteAddress", "RemoteIdentifier", "LocalIdentifier", "AuthenticationMethod", "ExtendedAuthEnabled", "ServerCertificateCommonName", "ServerCertificateIssuerCommonName", "IKESecurityAssociationParameters", "ChildSecurityAssociationParameters", "DisconnectOnSleep", "DisableMOBIKE", "DisableRedirect", "EnableCertificateRevocationCheck", "UseConfigurationAttributeInternalIPSubnet", "DeadPeerDetectionRate", "EnablePFS", "IncludeAllNetworks", "MTU"}
ENCRYPTION = {"AES-128": 3, "AES-256": 4, "AES-128-GCM": 5, "AES-256-GCM": 6, "ChaCha20Poly1305": 7}
INTEGRITY = {"SHA2-256": 3, "SHA2-384": 4, "SHA2-512": 5}

def read_profile(path):
    data = path.read_bytes()
    try: return plistlib.loads(data)
    except plistlib.InvalidFileException:
        # Verify CMS content signature. Signer trust is not asserted by -noverify.
        result = subprocess.run(["openssl", "cms", "-verify", "-inform", "DER", "-in", str(path), "-noverify"], capture_output=True, check=True)
        return plistlib.loads(result.stdout)

def inspect_sanitized(value):
    if isinstance(value, dict):
        if SECRETS.intersection(value): raise ValueError("Profile contains credentials or a client identity reference")
        for child in value.values(): inspect_sanitized(child)
    elif isinstance(value, list):
        for child in value: inspect_sanitized(child)

def import_configuration(profile):
    inspect_sanitized(profile)
    contents = profile.get("PayloadContent", [])
    roots = [p for p in contents if p.get("PayloadType") == "com.apple.security.root"]
    if len(roots) > 1 or any(p.get("PayloadType", "").startswith("com.apple.security.") and p.get("PayloadType") != "com.apple.security.root" for p in contents):
        raise ValueError("Only one public root CA payload is supported")
    payloads = [p for p in contents if p.get("PayloadType") == "com.apple.vpn.managed"]
    if len(payloads) != 1 or payloads[0].get("VPNType") != "IKEv2": raise ValueError("Expected one IKEv2 VPN payload")
    payload = payloads[0]
    allowed_payload = {"PayloadType", "PayloadVersion", "PayloadIdentifier", "PayloadUUID", "PayloadDisplayName", "PayloadDescription", "PayloadOrganization", "PayloadEnabled", "VPNType", "UserDefinedName", "IKEv2", "OnDemandEnabled", "OnDemandRules", "Proxies"}
    if set(payload) - allowed_payload: raise ValueError("Unsupported VPN payload settings")
    proxies = payload.get("Proxies", {})
    if set(proxies) - {"HTTPEnable", "HTTPSEnable"} or any(proxies.values()): raise ValueError("Enabled proxies need explicit support")
    settings = payload["IKEv2"]
    if set(settings) - SUPPORTED: raise ValueError("Unsupported IKEv2 settings")
    if settings.get("AuthenticationMethod") not in ("None", "Certificate") or settings.get("ExtendedAuthEnabled") != 1: raise ValueError("Only EAP username/password with server certificate validation is supported")
    trusted = []
    for rule in payload.get("OnDemandRules", []):
        if rule.get("Action") == "Disconnect" and rule.get("InterfaceTypeMatch") == "WiFi" and set(rule) <= {"Action", "InterfaceTypeMatch", "SSIDMatch"}:
            trusted.extend(rule.get("SSIDMatch", []))
        elif rule.get("Action") == "Connect" and set(rule) <= {"Action", "InterfaceTypeMatch"} and rule.get("InterfaceTypeMatch") in (None, "WiFi"):
            pass
        else: raise ValueError("Unsupported On Demand policy")
    trusted = [value.strip() for value in trusted]
    if len(set(trusted)) != len(trusted) or any(not value or len(value.encode()) > 32 for value in trusted): raise ValueError("Invalid trusted SSIDs")
    def association(value):
        if set(value) - {"EncryptionAlgorithm", "IntegrityAlgorithm", "DiffieHellmanGroup", "LifeTimeInMinutes"}: raise ValueError("Unsupported security association setting")
        return {"encryption": ENCRYPTION[value["EncryptionAlgorithm"]], "integrity": INTEGRITY[value["IntegrityAlgorithm"]], "diffieHellman": value["DiffieHellmanGroup"], "lifetimeMinutes": value["LifeTimeInMinutes"]}
    return {"server": settings["RemoteAddress"], "remoteIdentifier": settings["RemoteIdentifier"], "localIdentifier": settings.get("LocalIdentifier", ""),
            "authenticationMethod": settings["AuthenticationMethod"], "useExtendedAuthentication": True,
            "certificateCommonName": settings.get("ServerCertificateCommonName", ""), "certificateIssuerCommonName": settings.get("ServerCertificateIssuerCommonName", ""),
            "disconnectOnSleep": bool(settings.get("DisconnectOnSleep", 0)), "disableMOBIKE": bool(settings.get("DisableMOBIKE", 0)), "disableRedirect": bool(settings.get("DisableRedirect", 0)),
            "enableRevocationCheck": bool(settings.get("EnableCertificateRevocationCheck", 0)), "useConfigurationAttributeInternalIPSubnet": bool(settings.get("UseConfigurationAttributeInternalIPSubnet", 0)),
            "deadPeerDetectionRate": {"None": 0, "Low": 1, "Medium": 2, "High": 3}[settings.get("DeadPeerDetectionRate", "Medium")],
            "enablePFS": bool(settings.get("EnablePFS", 0)), "includeAllNetworks": bool(settings.get("IncludeAllNetworks", 0)), "mtu": settings.get("MTU"),
            "defaultTrustedSSIDs": trusted, "rootCertificateResource": "VPNRootCA" if roots else None,
            "ike": association(settings["IKESecurityAssociationParameters"]), "child": association(settings["ChildSecurityAssociationParameters"])}

def export_root(profile, directory):
    roots = [p for p in profile.get("PayloadContent", []) if p.get("PayloadType") == "com.apple.security.root"]
    if not roots: return
    data = roots[0]["PayloadContent"]
    if not isinstance(data, bytes): raise ValueError("Invalid certificate payload")
    # Validate certificate and normalize PEM/DER. No private keys are exported.
    result = subprocess.run(["openssl", "x509", "-inform", "PEM" if data.startswith(b"-----BEGIN CERTIFICATE") else "DER", "-outform", "DER"], input=data, capture_output=True, check=True)
    certificate = result.stdout
    (directory / "VPNRootCA.cer").write_bytes(certificate)
    root = {"PayloadType": "com.apple.security.root", "PayloadVersion": 1, "PayloadIdentifier": "uk.co.laingcorp.myvpn.root.certificate", "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, "uk.co.laingcorp.myvpn.root.certificate")), "PayloadDisplayName": "Family VPN Root CA", "PayloadContent": certificate}
    profile = {"PayloadType": "Configuration", "PayloadVersion": 1, "PayloadIdentifier": "uk.co.laingcorp.myvpn.root", "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_DNS, "uk.co.laingcorp.myvpn.root")), "PayloadDisplayName": "Family VPN Certificate Trust", "PayloadDescription": "Public root CA for the Family VPN server. Contains no VPN configuration or credentials.", "PayloadContent": [root]}
    (directory / "VPNRootCA.mobileconfig").write_bytes(plistlib.dumps(profile))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--output", type=Path, default=Path("MyVPN/Resources/VPNConfiguration.json"))
    args = parser.parse_args()
    try:
        profile = read_profile(args.profile)
        configuration = import_configuration(profile)
        export_root(profile, args.output.parent)
        args.output.write_text(json.dumps(configuration, indent=2) + "\n")
    except (ValueError, KeyError, TypeError, plistlib.InvalidFileException, subprocess.CalledProcessError):
        parser.exit(1, "Import rejected: profile contains unsupported settings, credentials, or invalid content.\n")
