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
