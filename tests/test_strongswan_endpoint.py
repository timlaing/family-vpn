"""Endpoint configuration validates boundaries and protects generated secrets."""
import importlib.util
from pathlib import Path
import subprocess
import pytest

ROOT=Path(__file__).resolve().parent.parent
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
