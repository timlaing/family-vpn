import pytest
import json
import plistlib
from pathlib import Path
from import_profile import import_configuration, read_profile
class TestImport:
    def profile(self):
        sa = {"EncryptionAlgorithm": "AES-256", "IntegrityAlgorithm": "SHA2-512", "DiffieHellmanGroup": 14, "LifeTimeInMinutes": 60}
        return {"PayloadContent": [{"PayloadType": "com.apple.vpn.managed", "VPNType": "IKEv2", "IKEv2": {"RemoteAddress": "vpn.example.org", "RemoteIdentifier": "vpn.example.org", "AuthenticationMethod": "None", "ExtendedAuthEnabled": 1, "IKESecurityAssociationParameters": sa, "ChildSecurityAssociationParameters": sa}}]}
    def test_bundled_template_requires_dashboard_provisioning(self):
        root = Path(__file__).resolve().parent.parent
        bundled = json.loads((root / "MyVPN/Resources/VPNConfiguration.json").read_text())
        assert bundled['server'] == 'gateway.invalid'
        assert bundled['remoteIdentifier'] == 'gateway.invalid'
        assert bundled['defaultTrustedSSIDs'] == []
        assert bundled['rootCertificateResource'] is None
        assert bundled['mtu'] is None
    def test_certificate_eap_flags_and_proxy_rejection(self):
        profile = self.profile()
        profile["PayloadContent"][0]["IKEv2"].update({"AuthenticationMethod": "Certificate", "DeadPeerDetectionRate": "High", "UseConfigurationAttributeInternalIPSubnet": True})
        result = import_configuration(profile)
        assert (result['deadPeerDetectionRate']) == (3)
        assert result['useConfigurationAttributeInternalIPSubnet']
        profile["PayloadContent"][0]["Proxies"] = {"HTTPEnable": 1}
        with pytest.raises(ValueError): import_configuration(profile)
    def test_settings_preserved(self):
        result = import_configuration(self.profile())
        assert (result['ike']['integrity']) == (5)
        assert (result['server']) == ('vpn.example.org')
    def test_secrets_and_unknown_settings_rejected(self):
        for key in ("AuthPassword", "CustomSetting"):
            profile = self.profile(); profile["PayloadContent"][0]["IKEv2"][key] = "redacted-test"
            with pytest.raises(ValueError): import_configuration(profile)
