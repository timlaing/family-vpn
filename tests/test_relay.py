"""Relay protocol, endpoint isolation and transient device-data integration tests."""
import socket
import time
import uuid
from unittest.mock import Mock, patch
import pytest
from family_vpn.app import Settings, create_app
from family_vpn.relay_protocol import body_bytes, server_key, signed_headers, signature
from family_vpn.relay_service import create_relay, PublicHTTPS
from family_vpn.relay_client import RelaySender, PushSender


class Sender:
    def __init__(self): self.calls = []
    def send(self, token, command=None):
        self.calls.append((token, command))
        return 'accepted'


@pytest.fixture
def relay(tmp_path):
    callbacks, sender = [], Sender()
    def receive(url, secret, payload):
        callbacks.append((url, secret, payload))
        return True
    app = create_relay(str(tmp_path/'relay.sqlite'), 'e'*32, 'm'*32, sender, callback_sender=receive)
    return app, app.test_client(), sender, callbacks


def enroll(client, server='vpn.example.org', token='t'*32, limit=10, extra=None):
    value = {'server':server, 'token':token, 'limit':limit, 'callback':'https://dashboard.example.org/family-vpn/relay-results'}
    body = body_bytes(value)
    headers = {**signed_headers(token, '/endpoints', body), 'Authorization':'Bearer '+'e'*32}
    return client.post('/endpoints', data=body, headers={**headers, **(extra or {})})


def send(client, server='vpn.example.org', secret='t'*32, extra=None):
    value = {'server':server, 'token':'ab'*32, 'device':str(uuid.uuid4()), 'command':None}
    body = body_bytes(value)
    headers = signed_headers(secret, '/push', body)
    return client.post('/push',data=body,headers={**headers, **(extra or {})}), value, body, headers


def test_registration_auth_callback_proof_and_takeover_prevention(relay):
    app, client, _, callbacks = relay
    assert enroll(client, extra={'Authorization':'wrong'}).status_code == 401
    assert enroll(client).status_code == 201
    assert callbacks[0][2] == {'server':'vpn.example.org', 'kind':'registration'}
    assert enroll(client, token='x'*32).status_code == 409
    assert enroll(client, extra={'X-Relay-Signature':'wrong'}).status_code == 401
    assert enroll(client, limit=11).status_code == 201
    assert app.extensions['relay_store'].endpoint('vpn.example.org')['quota'] == 11
    assert enroll(client, limit=101).status_code == 400


def test_callback_failure_does_not_register(tmp_path):
    app = create_relay(str(tmp_path/'relay.sqlite'),'e'*32,'m'*32,Sender(),callback_sender=lambda *args: False)
    assert enroll(app.test_client()).status_code == 400
    assert app.extensions['relay_store'].endpoint('vpn.example.org') is None


def test_signed_push_returns_to_owner_and_does_not_persist_devices(relay):
    app, client, sender, callbacks = relay
    assert enroll(client).status_code == 201
    response, value, _, _ = send(client)
    assert response.status_code == 200
    assert response.json == {'result':'accepted','callback':'delivered'}
    assert sender.calls == [(value['token'], None)]
    assert callbacks[-1][2] == {**{key:value[key] for key in ('server','device','token')}, 'kind':'push_result','result':'accepted'}
    with app.extensions['relay_store'].connect() as db:
        dump = '\n'.join(db.iterdump())
    for secret in (value['device'],value['token'],'t'*32): assert secret not in dump
    assert 'devices' not in dump


def test_replay_expiry_body_tampering_and_wrong_endpoint_secret(relay):
    _, client, sender, _ = relay
    enroll(client)
    response, value, body, headers = send(client)
    assert response.status_code == 200
    assert client.post('/push',data=body,headers=headers).status_code == 409
    value['token'] = 'cd'*32
    assert client.post('/push',data=body_bytes(value),headers=headers).status_code == 401
    old_time, nonce = str(int(time.time())-301), str(uuid.uuid4())
    old_headers = {**headers,'X-Relay-Time':old_time,'X-Relay-Nonce':nonce,
        'X-Relay-Signature':signature('t'*32,'POST','/push',body,old_time,nonce)}
    assert client.post('/push',data=body,headers=old_headers).status_code == 401
    assert send(client,secret='wrong')[0].status_code == 401
    assert len(sender.calls) == 1


def test_rate_limit_is_per_endpoint_and_survives_restart(relay):
    app, client, _, _ = relay
    enroll(client)
    enroll(client,server='other.example.org',token='o'*32)
    for _ in range(10): assert send(client)[0].status_code == 200
    assert send(client)[0].status_code == 429
    assert send(client,server='other.example.org',secret='o'*32)[0].status_code == 200
    restart = create_relay(app.extensions['relay_store'].path,'e'*32,'m'*32,Sender(),callback_sender=lambda *args: True)
    assert send(restart.test_client())[0].status_code == 429


def test_callback_rejects_internal_dns_and_pins_public_tls():
    address = (socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))
    with patch('socket.getaddrinfo',return_value=[address]), patch('socket.create_connection') as connect:
        with pytest.raises(ValueError): PublicHTTPS('dashboard.example.org').connect()
        connect.assert_not_called()
    public = (socket.AF_INET,socket.SOCK_STREAM,6,'',('1.1.1.1',443))
    with patch('socket.getaddrinfo',return_value=[public]), patch('socket.create_connection') as connect, patch('ssl.create_default_context') as tls:
        connection = PublicHTTPS('dashboard.example.org',timeout=10)
        connection.connect()
        connect.assert_called_once_with(('1.1.1.1',443),timeout=10)
        tls.return_value.wrap_socket.assert_called_once_with(connect.return_value,server_hostname='dashboard.example.org')


def test_canonical_server_identity():
    assert server_key('VPN.Example.org') == 'vpn.example.org'
    assert server_key('2001:db8:0:0::1') == '2001:db8::1'


def test_signed_callback_updates_owner_only_and_rejects_replay(tmp_path):
    settings = Settings(database=str(tmp_path/'owner.sqlite'),admin_secret='a'*32,enrollment_secret='e'*32,
        session_secret='s'*32,automatic=False,relay_secret='t'*32,relay_callback='https://dashboard.example.org/family-vpn/relay-results')
    owner = create_app(settings, Sender())
    settings.relay_server = 'vpn.example.org'
    client = owner.test_client()
    device = str(uuid.uuid4())
    client.post('/registrations',json={'id':device,'token':'ab'*32},headers={'Authorization':'Bearer '+'e'*32})
    value = {'server':'vpn.example.org','kind':'push_result','device':device,'token':'ab'*32,'result':'accepted'}
    body = body_bytes(value)
    headers = signed_headers('t'*32,'/family-vpn/relay-results',body)
    assert client.post('/relay-results',data=body,headers={**headers,'X-Relay-Signature':'wrong'}).status_code == 401
    assert client.post('/relay-results',data=body,headers=headers).status_code == 204
    assert client.post('/relay-results',data=body,headers=headers).status_code == 409
    assert owner.extensions['database'].public_devices()[0]['push_result'] == 'accepted'
    # A late invalid-token callback cannot erase a subsequently rotated APNs token.
    client.post('/registrations',json={'id':device,'token':'cd'*32},headers={'Authorization':'Bearer '+'e'*32})
    value['result'] = 'invalid_token'
    body = body_bytes(value)
    assert client.post('/relay-results',data=body,headers=signed_headers('t'*32,'/family-vpn/relay-results',body)).status_code == 204
    assert owner.extensions['database'].public_devices()[0]['registered_token']
    owner.extensions['dispatcher'].close()


def test_transport_selection_and_signed_client_requests():
    settings = Settings(push_mode='relay',relay_server='vpn.example.org',relay_registered_server='vpn.example.org',
        relay_secret='t'*32,relay_enrollment='e'*32,relay_url='https://push.example.org',relay_callback='https://dashboard.example.org/relay-results')
    sender = RelaySender(settings)
    response = Mock(status_code=200)
    response.json.return_value = {'result':'accepted'}
    with patch('httpx.Client') as client:
        client.return_value.__enter__.return_value.post.return_value = response
        assert sender.send('ab'*32,device=str(uuid.uuid4())) == 'accepted'
        request = client.return_value.__enter__.return_value.post.call_args.kwargs
        assert 'X-Relay-Signature' in request['headers']
        response.status_code = 429
        assert sender.send('ab'*32,device=str(uuid.uuid4())) == 'retry_later'
    mixed = PushSender(settings)
    with patch.object(mixed.direct,'send',return_value='direct') as direct, patch.object(mixed.relay,'send',return_value='relay'):
        assert mixed.send('ab'*32) == 'relay'
        direct.assert_not_called()
        settings.push_mode = 'direct'
        assert mixed.send('ab'*32) == 'direct'


def test_addon_relay_credentials_persist_and_invalid_edit_is_atomic(tmp_path):
    import json
    from family_vpn.addon import AddonConfiguration
    (tmp_path/'options.json').write_text(json.dumps({}))
    manager = AddonConfiguration(tmp_path)
    settings = manager.load()
    assert settings.push_mode == 'relay'
    assert settings.relay_url == 'https://push.family-vpn.workers.dev'
    assert len(settings.relay_secret) >= 32
    original = settings.relay_secret
    with pytest.raises(ValueError):
        manager.update({'interval':'1800','relay_token':'x'*32,'relay_enrollment':'short'},settings)
    assert (tmp_path/'relay-token').read_text() == original
    manager.update({'interval':'1800','relay_url':'https://relay.example.org',
        'relay_callback':'https://dashboard.example.org/family-vpn/relay-results',
        'relay_enrollment':'e'*32},settings)
    settings.relay_registered_server = 'vpn.example.org'
    manager.save_settings(settings)
    reloaded = manager.load()
    assert reloaded.relay_registered_server == 'vpn.example.org'
    assert reloaded.relay_secret == original
    assert reloaded.relay_enrollment == 'e'*32
    manager.update({'reset':'true'},reloaded)
    assert manager.load().relay_registered_server == 'vpn.example.org'
    saved = json.loads(manager.path.read_text())
    saved.pop('push_mode')
    manager.path.write_text(json.dumps(saved))
    assert manager.load().push_mode == 'direct'


def test_non_ascii_registration_token_is_rejected(relay):
    assert enroll(relay[1], token='é'*32).status_code == 400


def test_future_timestamp_nonce_remains_blocked_for_entire_validity(relay):
    _, client, _, _ = relay
    enroll(client)
    now = int(time.time())
    value = {'server':'vpn.example.org','token':'ab'*32,'device':str(uuid.uuid4()),'command':None}
    body = body_bytes(value)
    timestamp, nonce = str(now+299), str(uuid.uuid4())
    headers = {'Content-Type':'application/json','X-Relay-Time':timestamp,'X-Relay-Nonce':nonce,
        'X-Relay-Signature':signature('t'*32,'POST','/push',body,timestamp,nonce)}
    assert client.post('/push',data=body,headers=headers).status_code == 200
    with patch('time.time',return_value=now+301):
        assert client.post('/push',data=body,headers=headers).status_code == 409


def test_signed_command_envelope_is_forwarded_unchanged(relay):
    _, client, sender, callbacks = relay
    enroll(client)
    envelope = {'body':'eyJhY3Rpb24iOiJlbmFibGUifQ==','signature':'owner-signature'}
    value = {'server':'vpn.example.org','token':'ab'*32,'device':str(uuid.uuid4()),'command':envelope}
    body = body_bytes(value)
    response = client.post('/push',data=body,headers=signed_headers('t'*32,'/push',body))
    assert response.status_code == 200
    assert sender.calls == [(value['token'],envelope)]
    assert 'command' not in callbacks[-1][2]
