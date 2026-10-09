import re
import base64
import hashlib
import json
import pytest
import test_app
from family_vpn.administrator import AdministratorProvisioning

class TestAdministrator:
    setup_method=test_app.TestApp.setup_method
    teardown_method=test_app.TestApp.teardown_method
    login=test_app.TestApp.login
    register=test_app.TestApp.register
    def headers(self):
        return {'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Administrator-Protocol':'1','X-FamilyVPN-Command-Protocol':'1'}
    def setup_password(self,password='dashboard-test-password'):
        self.login()
        csrf = re.search(r'name="csrf" value="([^" ]+)"', self.client.get("/login").text).group(1)
        return self.client.post('/administrator-password',data={'csrf':csrf,'password':password,'confirmation':password})
    def test_setup_requires_dashboard_session_csrf_and_matching_password(self):
        assert (self.client.post('/administrator-password', data={}).status_code) == (403)
        self.login()
        assert (self.client.post('/administrator-password', data={}).status_code) == (403)
        csrf = re.search(r'name="csrf" value="([^" ]+)"', self.client.get("/login").text).group(1)
        for password,confirmation in [('short','short'),('long-test-password','different')]:
            assert (self.client.post('/administrator-password', data={'csrf': csrf, 'password': password, 'confirmation': confirmation}).status_code) == (400)
        assert (self.client.post('/administrator-password', data={'csrf': csrf, 'password': 'x' * 1025, 'confirmation': 'x' * 1025}).status_code) == (413)
        assert not (self.app.extensions['administrator'].configured())
        assert (self.setup_password().status_code) == (302)
        assert ('dashboard-test-password') not in (self.client.get('/').text)
    def test_bootstrap_without_apns_requires_setup_and_provisions_only_verifier(self):
        payload={'id':self.device,'token':None}
        assert (self.client.post('/registrations', headers=self.headers(), json=payload).status_code) == (409)
        assert (self.database.public_devices()) == ([])
        self.setup_password()
        response=self.client.post('/registrations',headers=self.headers(),json=payload)
        assert (response.status_code) == (201)
        provision=response.json['administrator']
        expected=hashlib.pbkdf2_hmac('sha256',b'dashboard-test-password',base64.b64decode(provision['salt']),600000,32)
        assert (base64.b64decode(provision['verifier'])) == (expected)
        assert ('dashboard-test-password') not in (response.text)
        assert (provision['iterations']) == (600000)
        assert not (self.database.public_devices()[0]['registered_token'])
        restored=AdministratorProvisioning(self.database).enrollment()
        assert (restored) == (provision)
    def test_rotation_updates_future_registrations_and_preserves_existing_apns_token(self):
        self.setup_password()
        self.register()
        first=self.client.post('/registrations',headers=self.headers(),json={'id':self.device,'token':None}).json['administrator']
        assert self.database.public_devices()[0]['registered_token']
        self.setup_password('replacement-test-password')
        second=self.client.post('/registrations',headers=self.headers(),json={'id':self.device,'token':None}).json['administrator']
        assert (first['revision']) != (second['revision'])
        assert (first['verifier']) != (second['verifier'])
        with self.database.connect() as db:
            assert (db.execute('SELECT token FROM devices WHERE id=?', (self.device,)).fetchone()[0]) == ('ab' * 32)
    def test_verifier_is_not_exposed_in_dashboard_reports_or_legacy_registration(self):
        self.setup_password()
        provision=self.app.extensions['administrator'].enrollment()
        for path in ('/','/api/devices','/api/commands'):
            response=self.client.get(path,headers={'Authorization':'Bearer '+self.settings.admin_secret})
            assert (provision['verifier']) not in (response.text)
            assert (provision['salt']) not in (response.text)
        response=self.client.post('/registrations',headers={'Authorization':'Bearer '+self.settings.enrollment_secret},json={'id':self.device,'token':'ab'*32})
        assert ('administrator') not in (response.json)
        assert (self.client.post('/registrations', headers=self.headers() | {'Authorization': 'Bearer wrong'}, json={'id': self.device, 'token': None}).status_code) == (401)
