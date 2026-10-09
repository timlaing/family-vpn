import base64
import json
import time
from cryptography.exceptions import InvalidSignature
import pytest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import test_app
from family_vpn.commands import Commands

class CommandSender(test_app.Sender):
    def send(self, token, command=None):
        self.command=command
        return super().send(token)

class TestCommand:
    register=test_app.TestApp.register
    login=test_app.TestApp.login
    teardown_method=test_app.TestApp.teardown_method
    # Inherited authentication/storage cases also exercise the migrated database.
    def setup_method(self):
        test_app.TestApp.setup_method(self)
        self.sender=CommandSender()
        self.dispatcher.sender=self.sender
        self.commands=self.app.extensions['commands']
        response=self.client.post('/registrations',headers={'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Command-Protocol':'1'},json={'id':self.device,'token':'ab'*32})
        self.credential=response.json['status_token']
        self.public=response.json['command_key']
        self.epoch=response.json['command_epoch']
    def queue(self,action='refresh_status',**extra):
        response=self.client.post('/api/commands',headers={'Authorization':'Bearer '+self.settings.admin_secret},json={'id':self.device,'action':action,**extra})
        if response.status_code==202 and self.dispatcher.future: self.dispatcher.future.result(timeout=2)
        return response
    def ack(self,request_id,result='executed',credential=None):
        return self.client.post('/command-results',headers={'Authorization':'Bearer '+(credential or self.credential)},json={'id':self.device,'request_id':request_id,'result':result})
    def test_signed_payload_has_device_scope_and_verified_signature(self):
        response=self.queue('suspend',duration_seconds=900)
        assert (response.status_code) == (202)
        envelope=self.sender.command
        raw=base64.b64decode(envelope['body'])
        key=Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public))
        key.verify(base64.b64decode(envelope['signature']),raw)
        body=json.loads(raw)
        assert (body['device']) == (self.device)
        assert (body['epoch']) == (self.epoch)
        assert (body['suspend_until'] - body['issued_at']) == (900)
        assert (body['request_id']) == (response.json['request_id'])
        assert ('status_token') not in (body)
        assert ('token') not in (body)
        signature = base64.b64decode(envelope['signature'])
        with pytest.raises(InvalidSignature): key.verify(signature, raw+b' ')
        row=self.commands.public()[0]
        assert (row['state']) == ('pending')
        assert (row['delivery']) == ('accepted')
    def test_auth_validation_and_legacy_enrollment(self):
        assert (self.client.post('/api/commands', json={}).status_code) == (401)
        for value in ({'action':'disconnect'},{'duration_seconds':True},{'duration_seconds':1},{'duration_seconds':90000},{'password':'private'}):
            assert (self.queue(value.pop('action', 'suspend'), **value).status_code) == (400)
        old_device='12345678-1234-1234-1234-123456789abc';self.register(device=old_device)
        with pytest.raises(RuntimeError): self.commands.queue(old_device,'enable')
        assert (self.client.get('/commands', query_string={'id': self.device}).status_code) == (401)
    def test_scoped_fetch_and_ack_is_idempotent(self):
        request_id=self.queue().json['request_id']
        headers={'Authorization':'Bearer '+self.credential}
        response=self.client.get('/commands',query_string={'id':self.device},headers=headers)
        assert (response.status_code) == (200);assert (len(response.json['commands'])) == (1)
        other='12345678-1234-1234-1234-123456789abc';self.register(device=other)
        assert (self.client.get('/commands', query_string={'id': other}, headers=headers).status_code) == (401)
        assert (self.ack(request_id, credential='wrong').status_code) == (401)
        assert (self.ack(request_id).status_code) == (204)
        assert (self.ack(request_id).status_code) == (204)
        assert (self.ack(request_id, 'failed').status_code) == (409)
        assert (self.commands.public()[0]['state']) == ('executed')
        assert (self.commands.pending(self.device)) == ([])
    def test_control_supersession_and_refresh_does_not_cancel_control(self):
        first=self.queue('suspend',duration_seconds=None).json['request_id']
        ping=self.queue().json['request_id']
        assert (len(self.commands.pending(self.device))) == (2)
        last=self.queue('enable').json['request_id']
        history={row['request_id']:row for row in self.commands.public()}
        assert (history[first]['state']) == ('superseded')
        assert (history[ping]['state']) == ('pending')
        assert (history[last]['state']) == ('pending')
        pending=[json.loads(base64.b64decode(row['body'])) for row in self.commands.pending(self.device)]
        assert ([row['sequence'] for row in pending]) == (sorted((row['sequence'] for row in pending)))
    def test_expiration_and_late_acknowledgement(self):
        request_id=self.queue('suspend',duration_seconds=900).json['request_id']
        with patch('family_vpn.commands.time.time',return_value=time.time()+1000):
            assert (self.commands.pending(self.device)) == ([])
            assert (self.commands.public()[0]['state']) == ('expired')
        assert (self.ack(request_id).status_code) == (204)
        assert (self.commands.public()[0]['state']) == ('executed')
    def test_rotation_revokes_old_epoch_and_key_persists(self):
        request_id=self.queue().json['request_id']
        response=self.client.post('/registrations',headers={'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Command-Protocol':'1'},json={'id':self.device,'token':'cd'*32})
        assert (response.json['command_epoch']) != (self.epoch)
        assert (response.json['command_key']) == (self.public)
        assert (self.ack(request_id).status_code) == (401)
        self.credential=response.json['status_token']
        assert (self.ack(request_id).status_code) == (409)
        assert (Commands(self.database).public_key) == (self.public)
        from pathlib import Path
        assert ((Path(self.settings.database).parent / 'command-signing.key').stat().st_mode & 511) == (384)
    def test_retry_is_rate_limited_and_terminal_commands_stop(self):
        request_id=self.queue().json['request_id']
        assert (self.commands.next_delivery(self.device)) is None
        with self.database.connect() as db: db.execute('UPDATE commands SET last_attempt=0 WHERE request_id=?',(request_id,))
        assert (self.commands.next_delivery(self.device)) is not None
        self.ack(request_id)
        assert (self.commands.next_delivery(self.device)) is None
    def test_dashboard_requires_csrf_for_policy_commands(self):
        self.login()
        assert (self.client.post('/command', data={'id': self.device, 'action': 'enable'}).status_code) == (403)
        with self.client.session_transaction() as session: csrf=session['csrf']
        response=self.client.post('/command',data={'csrf':csrf,'id':self.device,'action':'suspend','duration_seconds':'manual'})
        assert (response.status_code) == (302)
        self.dispatcher.future.result(timeout=2)
        assert (self.commands.public()[0]['suspend_until']) is None

    def test_public_reports_do_not_claim_protected_contact(self):
        headers={'Authorization':'Bearer '+self.credential}
        body={'id':self.device,'connection':'connected','policy_ok':True}
        assert (self.client.post('/status', headers=headers, json=body).status_code) == (204)
        with self.database.connect() as db:
            assert (db.execute('SELECT tunnel_seen FROM devices WHERE id=?', (self.device,)).fetchone()[0]) is None
        assert (self.client.get('/commands', query_string={'id': self.device}, headers=headers).status_code) == (200)
        with self.database.connect() as db:
            assert (db.execute('SELECT tunnel_seen FROM devices WHERE id=?', (self.device,)).fetchone()[0]) is not None
        for credential in (self.settings.admin_secret,self.settings.enrollment_secret):
            assert (self.client.post('/status', headers={'Authorization': 'Bearer ' + credential}, json=body).status_code) == (401)

    def test_public_reporting_credential_rate_limit(self):
        headers={'Authorization':'Bearer '+self.credential}
        body={'id':self.device,'connection':'disconnected','policy_ok':True}
        for _ in range(20):
            assert (self.client.post('/status', headers=headers, json=body).status_code) == (204)
        assert (self.client.post('/status', headers=headers, json=body).status_code) == (429)
        with patch('family_vpn.app.time.monotonic',return_value=time.monotonic()+61):
            assert (self.client.post('/status', headers=headers, json=body).status_code) == (204)

    def test_reprovision_snapshots_verifier_and_does_not_supersede_vpn_policy(self):
        self.app.extensions['administrator'].set_password('dashboard-test-password','dashboard-test-password')
        headers={'Authorization':'Bearer '+self.settings.enrollment_secret,'X-FamilyVPN-Command-Protocol':'1','X-FamilyVPN-Administrator-Protocol':'1'}
        response=self.client.post('/registrations',headers=headers,json={'id':self.device,'token':'ab'*32})
        self.credential=response.json['status_token']
        original=response.json['administrator']
        suspend=self.queue('suspend',duration_seconds=900).json['request_id']
        first=self.queue('reprovision_admin').json['request_id']
        body=json.loads(base64.b64decode(self.sender.command['body']))
        assert (body['administrator']) == (original)
        key=Ed25519PublicKey.from_public_bytes(base64.b64decode(self.public))
        key.verify(base64.b64decode(self.sender.command['signature']),base64.b64decode(self.sender.command['body']))
        self.app.extensions['administrator'].set_password('replacement-test-password','replacement-test-password')
        assert (json.loads(base64.b64decode(self.commands.pending(self.device)[1]['body']))['administrator']) == (original)
        last=self.queue('reprovision_admin').json['request_id']
        self.queue('refresh_status')
        pending=[json.loads(base64.b64decode(value['body'])) for value in self.commands.pending(self.device)]
        assert (len(pending)) == (3)
        assert (next((value for value in pending if value['action'] == 'reprovision_admin'))['administrator']['revision']) != (original['revision'])
        states={row['request_id']:row['state'] for row in self.commands.public()}
        assert (states[first]) == ('superseded')
        assert (states[suspend]) == ('pending')
        assert (self.ack(last).status_code) == (204)
        response=self.client.get('/api/commands',headers={'Authorization':'Bearer '+self.settings.admin_secret})
        assert (original['verifier']) not in (response.text)
        assert ('administrator_json') not in (response.text)
    def test_reprovision_requires_updated_registration_and_rejects_extra_parameters(self):
        assert (self.queue('reprovision_admin').status_code) == (409)
        assert (self.queue('reprovision_admin', duration_seconds=900).status_code) == (400)
