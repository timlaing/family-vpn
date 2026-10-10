"""Endpoint configuration validates boundaries and protects generated secrets."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import pytest

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "strongswan-endpoint"))
spec=importlib.util.spec_from_file_location('endpoint',ROOT/'strongswan-endpoint/configure.py')
endpoint=importlib.util.module_from_spec(spec)
spec.loader.exec_module(endpoint)


def test_endpoint_rejects_overlaps_injection_and_unbounded_private_access():
    for server,pool,username,allowed in [
        ('vpn.example.org;unsafe','10.20.30.0/24','device','192.168.10.53/32'),
        ('192.168.10.1','10.20.30.0/24','device','192.168.10.53/32'),
        ('vpn.example.org','192.168.10.0/24','device','192.168.10.53/32'),
        ('vpn.example.org','10.20.30.0/24','device"injection','192.168.10.53/32'),
        ('vpn.example.org','10.20.30.0/24','device','0.0.0.0/0'),
        ('vpn.example.org','10.20.30.0/24','device','192.168.20.0/24'),
    ]:
        with pytest.raises(ValueError):endpoint.validate(server,pool,'192.168.10.53',username,'192.168.10.0/24',allowed)


def test_generated_certificates_and_secrets_are_private_and_not_overwritten(tmp_path):
    output=tmp_path/'runtime'
    endpoint.create(output,'vpn.example.org','10.20.30.0/29','192.168.10.53','device','synthetic-test-password','192.168.10.0/24','192.168.10.53/32')
    secrets=output/'swanctl/conf.d/family-vpn-secrets.conf'
    assert secrets.stat().st_mode & 0o777==0o600
    assert (output/'ca/ca-key.pem').stat().st_mode & 0o777==0o600
    assert not (output/'swanctl/x509ca/family-vpn-ca.srl').exists()
    assert '10.20.30.1-10.20.30.6' in (output/'swanctl/swanctl.conf').read_text()
    cert=output/'swanctl/x509/vpn-server.pem'
    result=subprocess.run(['openssl','verify','-CAfile',str(output/'swanctl/x509ca/family-vpn-ca.pem'),'-verify_hostname','vpn.example.org',str(cert)],capture_output=True,text=True,check=True)
    assert 'OK' in result.stdout
    detail=subprocess.run(['openssl','x509','-in',str(cert),'-noout','-text'],capture_output=True,text=True,check=True).stdout
    assert 'CA:FALSE' in detail and 'DNS:vpn.example.org' in detail and 'TLS Web Server Authentication' in detail
    original=secrets.read_bytes()
    with pytest.raises(ValueError):endpoint.create(output,'vpn.example.org','10.20.30.0/24','192.168.10.53','device','synthetic-test-password','192.168.10.0/24','192.168.10.53/32')
    assert secrets.read_bytes()==original


def test_radius_validation_and_rendering_preserve_certificate_and_local_accounts(tmp_path):
    from authentication import configure_authentication, radius_settings
    for invalid in [
        {"server": "https://radius.example.org"}, {"server": "radius.example.org\nunsafe"},
        {"secret": 'unsafe"radius-secret'}, {"secret": "short"},
        {"auth_port": 0}, {"acct_port": 65536}, {"auth_port": "bad"},
        {"nas_identifier": 'unsafe"nas'},
    ]:
        fields = dict(server="192.168.10.54", secret="synthetic-radius-secret", auth_port=1812,
                      acct_port=1813, nas_identifier="family-vpn", accounting=False)
        fields.update(invalid)
        with pytest.raises(ValueError):
            radius_settings({}, **fields)
    output = tmp_path / "runtime"
    endpoint.create(output, "vpn.example.org", "10.20.30.0/24", "192.168.10.53", "device", "synthetic-vpn-password", "192.168.10.0/24", "192.168.10.53/32")
    cert = (output / "swanctl/x509/vpn-server.pem").read_bytes()
    credentials = (output / "swanctl/conf.d/family-vpn-secrets.conf").read_bytes()
    configure_authentication(output, "radius", "radius.example.org", "synthetic-radius-secret")
    assert "auth = eap-radius" in (output / "swanctl/swanctl.conf").read_text()
    assert "accounting = no" in (output / "authentication/radius.conf").read_text()
    assert (output / "swanctl/x509/vpn-server.pem").read_bytes() == cert
    assert (output / "swanctl/conf.d/family-vpn-secrets.conf").read_bytes() == credentials
    configure_authentication(output, "local")
    assert not (output / "authentication/radius.conf").exists()
    assert "auth = eap-mschapv2" in (output / "swanctl/swanctl.conf").read_text()


def test_radius_cli_prompts_for_secret_without_local_account(tmp_path, monkeypatch, capsys):
    output = tmp_path / "runtime"
    monkeypatch.setattr(sys, "argv", ["configure.py", "--auth", "radius", "--radius-server", "radius.example.org",
                                    "--server", "vpn.example.org", "--dns", "192.168.10.53",
                                    "--lan", "192.168.10.0/24", "--allow-lan", "192.168.10.53/32",
                                    "--output", str(output)])
    monkeypatch.setattr(endpoint.getpass, "getpass", lambda prompt: "synthetic-radius-secret")
    endpoint.main()
    assert "auth = eap-radius" in (output / "swanctl/swanctl.conf").read_text()
    assert "synthetic-radius-secret" in (output / "authentication/radius.conf").read_text()
    assert "synthetic-radius-secret" not in capsys.readouterr().out
    assert (output / "swanctl/conf.d/family-vpn-secrets.conf").read_text() == "secrets {\n}\n"
