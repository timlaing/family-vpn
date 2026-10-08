import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import uuid
import pytest
from test_app import TestApp as AppFixture
from family_vpn.provisioning import VPNProvisioning

class TestProvisioning:
    setup_method = AppFixture.setup_method
    teardown_method = AppFixture.teardown_method
    login = AppFixture.login
    def test_dashboard_configuration_requires_authentication_and_csrf(self):
        assert self.client.post('/vpn-provisioning').status_code == 401
        self.login()
        assert self.client.post('/vpn-provisioning', data={'server':'vpn.example.org'}).status_code == 403
        with self.client.session_transaction() as session: csrf = session['csrf']
        response = self.client.post('/vpn-provisioning', data={'csrf':csrf,'server':'vpn.example.org','trusted_ssids':'Home Wi-Fi\nOffice'})
        assert response.status_code == 302
        assert self.app.extensions['vpn_provisioning'].enrollment()['trustedSSIDs'] == ['Home Wi-Fi','Office']

    def test_enrollment_requires_configuration_and_returns_current_settings(self):
        headers = {'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-VPN-Protocol':'1'}
        payload = {'id':self.device,'token':'ab'*32}
        assert self.client.post('/registrations', headers=headers, json=payload).status_code == 409
        assert self.database.public_devices() == []
        provisioning = self.app.extensions['vpn_provisioning']
        first = provisioning.save('vpn.example.org','',['Home'])
        response = self.client.post('/registrations', headers=headers, json=payload)
        assert response.status_code == 201
        assert response.json['vpn'] == first
        second = provisioning.save('new.example.org','identity.example.org',[])
        assert second['revision'] != first['revision']
        assert VPNProvisioning(self.database).enrollment() == second
        assert self.client.post('/registrations', headers=headers, json=payload).json['vpn'] == second

@pytest.mark.parametrize('host',['https://vpn.example.org','vpn.example.org:443','a..org','gateway.invalid',' x.org','a'*64+'.org'])
def test_invalid_gateway(host):
    with pytest.raises(ValueError): VPNProvisioning.hostname(host)

@pytest.mark.parametrize('host',['vpn.example.org','203.0.113.1','2001:db8::1'])
def test_valid_gateway(host):
    assert VPNProvisioning.hostname(host) == host

class TestVPNPush:
    setup_method = AppFixture.setup_method
    teardown_method = AppFixture.teardown_method
    def test_snapshot_digest_authentication_and_supersession(self):
        self.app.extensions['vpn_provisioning'].save('vpn.example.org','',['Home'])
        headers = {'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Command-Protocol':'1','X-FamilyVPN-VPN-Protocol':'2'}
        registration = self.client.post('/registrations',headers=headers,json={'id':self.device,'token':'ab'*32}).json
        commands = self.app.extensions['commands']
        request_id = commands.queue(self.device,'reprovision_vpn')
        envelope = commands.pending(self.device)[0]
        body = json.loads(base64.b64decode(envelope['body']))
        assert len(json.dumps(envelope)) < 4096
        url = '/vpn-configuration?id='+self.device+'&request_id='+request_id
        assert self.client.get(url).status_code == 401
        auth = {'Authorization':'Bearer '+registration['status_token']}
        snapshot = self.client.get(url,headers=auth)
        assert hashlib.sha256(snapshot.data).hexdigest() == body['vpn_digest']
        self.app.extensions['vpn_provisioning'].save('new.example.org','',[])
        assert self.client.get(url,headers=auth).json['server'] == 'vpn.example.org'
        commands.queue(self.device,'reprovision_vpn')
        assert self.client.get(url,headers=auth).status_code == 404

    def test_ca_registration_and_validation(self):
        key = rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic test CA')])
        now = datetime.now(timezone.utc)
        certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=1)).not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256())
        pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        provisioning = self.app.extensions['vpn_provisioning']
        value = provisioning.save('vpn.example.org','',[],pem)
        assert base64.b64decode(value['caCertificate']) == certificate.public_bytes(serialization.Encoding.DER)
        with pytest.raises(ValueError): provisioning.save('vpn.example.org','',[],'invalid')
        headers = {'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-VPN-Protocol':'1'}
        assert self.client.post('/registrations',headers=headers,json={'id':self.device,'token':'ab'*32}).json['vpn']['caCertificate'] == value['caCertificate']
        assert provisioning.save('vpn.example.org','',[])['caCertificate'] is None
