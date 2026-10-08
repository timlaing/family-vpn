import base64
import hashlib
import json
import unittest
import test_app
from family_vpn.administrator import AdministratorProvisioning

class AdministratorTests(unittest.TestCase):
    setUp=test_app.AppTests.setUp
    tearDown=test_app.AppTests.tearDown
    login=test_app.AppTests.login
    register=test_app.AppTests.register
    def headers(self):
        return {'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Administrator-Protocol':'1','X-FamilyVPN-Command-Protocol':'1'}
    def setup_password(self,password='dashboard-test-password'):
        self.login()
        with self.client.session_transaction() as session: csrf=session['csrf']
        return self.client.post('/administrator-password',data={'csrf':csrf,'password':password,'confirmation':password})
    def test_setup_requires_dashboard_session_csrf_and_matching_password(self):
        self.assertEqual(self.client.post('/administrator-password',data={}).status_code,401)
        self.login()
        self.assertEqual(self.client.post('/administrator-password',data={}).status_code,403)
        with self.client.session_transaction() as session: csrf=session['csrf']
        for password,confirmation in [('short','short'),('long-test-password','different')]:
            self.assertEqual(self.client.post('/administrator-password',data={'csrf':csrf,'password':password,'confirmation':confirmation}).status_code,400)
        self.assertEqual(self.client.post('/administrator-password',data={'csrf':csrf,'password':'x'*1025,'confirmation':'x'*1025}).status_code,413)
        self.assertFalse(self.app.extensions['administrator'].configured())
        self.assertEqual(self.setup_password().status_code,302)
        self.assertNotIn('dashboard-test-password',self.client.get('/').text)
    def test_bootstrap_without_apns_requires_setup_and_provisions_only_verifier(self):
        payload={'id':self.device,'token':None}
        self.assertEqual(self.client.post('/registrations',headers=self.headers(),json=payload).status_code,409)
        self.assertEqual(self.database.public_devices(),[])
        self.setup_password()
        response=self.client.post('/registrations',headers=self.headers(),json=payload)
        self.assertEqual(response.status_code,201)
        provision=response.json['administrator']
        expected=hashlib.pbkdf2_hmac('sha256',b'dashboard-test-password',base64.b64decode(provision['salt']),600000,32)
        self.assertEqual(base64.b64decode(provision['verifier']),expected)
        self.assertNotIn('dashboard-test-password',response.text)
        self.assertEqual(provision['iterations'],600000)
        self.assertFalse(self.database.public_devices()[0]['registered_token'])
        restored=AdministratorProvisioning(self.database).enrollment()
        self.assertEqual(restored,provision)
    def test_rotation_updates_future_registrations_and_preserves_existing_apns_token(self):
        self.setup_password()
        self.register()
        first=self.client.post('/registrations',headers=self.headers(),json={'id':self.device,'token':None}).json['administrator']
        self.assertTrue(self.database.public_devices()[0]['registered_token'])
        self.setup_password('replacement-test-password')
        second=self.client.post('/registrations',headers=self.headers(),json={'id':self.device,'token':None}).json['administrator']
        self.assertNotEqual(first['revision'],second['revision'])
        self.assertNotEqual(first['verifier'],second['verifier'])
        with self.database.connect() as db:
            self.assertEqual(db.execute('SELECT token FROM devices WHERE id=?',(self.device,)).fetchone()[0],'ab'*32)
    def test_verifier_is_not_exposed_in_dashboard_reports_or_legacy_registration(self):
        self.setup_password()
        provision=self.app.extensions['administrator'].enrollment()
        for path in ('/','/api/devices','/api/commands'):
            response=self.client.get(path,headers={'Authorization':'Bearer '+self.settings.admin_secret})
            self.assertNotIn(provision['verifier'],response.text)
            self.assertNotIn(provision['salt'],response.text)
        response=self.client.post('/registrations',headers={'Authorization':'Bearer '+self.settings.enrollment_secret},json={'id':self.device,'token':'ab'*32})
        self.assertNotIn('administrator',response.json)
        self.assertEqual(self.client.post('/registrations',headers=self.headers()|{'Authorization':'Bearer wrong'},json={'id':self.device,'token':None}).status_code,401)
