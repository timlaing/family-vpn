import unittest
import json
import plistlib
from pathlib import Path
from import_profile import import_configuration, read_profile
class ImportTests(unittest.TestCase):
    def profile(self):
        sa = {"EncryptionAlgorithm": "AES-256", "IntegrityAlgorithm": "SHA2-512", "DiffieHellmanGroup": 14, "LifeTimeInMinutes": 60}
        return {"PayloadContent": [{"PayloadType": "com.apple.vpn.managed", "VPNType": "IKEv2", "IKEv2": {"RemoteAddress": "vpn.example.org", "RemoteIdentifier": "vpn.example.org", "AuthenticationMethod": "None", "ExtendedAuthEnabled": 1, "IKESecurityAssociationParameters": sa, "ChildSecurityAssociationParameters": sa}}]}
    def test_signed_project_profile_matches_bundle(self):
        root = Path(__file__).resolve().parent.parent
        source = read_profile(root / "VPN-EAP.mobileconfig")
        imported = import_configuration(source)
        bundled = json.loads((root / "MyVPN/Resources/VPNConfiguration.json").read_text())
        self.assertEqual(imported, bundled)
        ca_profile = plistlib.loads((root / "MyVPN/Resources/VPNRootCA.mobileconfig").read_bytes())
        self.assertEqual(len(ca_profile["PayloadContent"]), 1)
        self.assertEqual(ca_profile["PayloadContent"][0]["PayloadType"], "com.apple.security.root")
        self.assertEqual(ca_profile["PayloadContent"][0]["PayloadContent"], (root / "MyVPN/Resources/VPNRootCA.cer").read_bytes())
        self.assertEqual(imported["authenticationMethod"], "Certificate")
        self.assertEqual(len(imported["defaultTrustedSSIDs"]), 2)
        self.assertIsNone(imported["mtu"])
    def test_certificate_eap_flags_and_proxy_rejection(self):
        profile = self.profile()
        profile["PayloadContent"][0]["IKEv2"].update({"AuthenticationMethod": "Certificate", "DeadPeerDetectionRate": "High", "UseConfigurationAttributeInternalIPSubnet": True})
        result = import_configuration(profile)
        self.assertEqual(result["deadPeerDetectionRate"], 3)
        self.assertTrue(result["useConfigurationAttributeInternalIPSubnet"])
        profile["PayloadContent"][0]["Proxies"] = {"HTTPEnable": 1}
        with self.assertRaises(ValueError): import_configuration(profile)
    def test_settings_preserved(self):
        result = import_configuration(self.profile())
        self.assertEqual(result["ike"]["integrity"], 5)
        self.assertEqual(result["server"], "vpn.example.org")
    def test_secrets_and_unknown_settings_rejected(self):
        for key in ("AuthPassword", "CustomSetting"):
            profile = self.profile(); profile["PayloadContent"][0]["IKEv2"][key] = "redacted-test"
            with self.assertRaises(ValueError): import_configuration(profile)
if __name__ == "__main__": unittest.main()
