"""Endpoint lifecycle, uploaded APNs credentials and private proxy integration."""
import io
import json
import time
import uuid
from unittest.mock import patch
import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from werkzeug.datastructures import FileStorage
from family_vpn.addon import AddonConfiguration
from family_vpn.app import create_app
from family_vpn.relay_host import install_relay, HostedSender
from family_vpn.relay_protocol import body_bytes, signed_headers
from family_vpn.relay_service import create_relay
from family_vpn.relay_client import RelaySender
from family_vpn.ingress import IngressMiddleware, IngressSessionInterface


class Sender:
    def send(self, token, command=None): return 'accepted'


def key_upload():
    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    value = {'key_id':'ABCDEFGHIJ','team_id':'0123456789','private_key':pem}
    return FileStorage(stream=io.BytesIO(json.dumps(value).encode()),filename='credentials.json'),value


def manager_for(path):
    path.mkdir(exist_ok=True)
    (path/'options.json').write_text('{}')
    manager = AddonConfiguration(path)
    return manager,manager.load()


def register(client,secret='t'*32):
    body = body_bytes({'server':'vpn.example.org','callback':'https://owner.example.org/family-vpn/relay-results','token':secret,'limit':10})
    return client.post('/endpoints',data=body,headers={**signed_headers(secret,'/endpoints',body),'Authorization':'Bearer '+'e'*32})


def rotate(client,old='t'*32,new='n'*32):
    body = body_bytes({'server':'vpn.example.org','callback':'https://owner.example.org/family-vpn/relay-results','token':new})
    return client.post('/rotate',data=body,headers=signed_headers(old,'/rotate',body))


def push(client,secret='t'*32):
    body = body_bytes({'server':'vpn.example.org','device':str(uuid.uuid4()),'token':'ab'*32,'command':None})
    return client.post('/push',data=body,headers=signed_headers(secret,'/push',body))


def test_rotation_requires_current_key_and_old_key_stops_working(tmp_path):
    relay = create_relay(str(tmp_path/'relay.sqlite'),'e'*32,'m'*32,Sender(),callback_sender=lambda *args: True)
    client = relay.test_client()
    assert register(client).status_code == 201
    assert register(client).status_code == 409
    assert rotate(client,old='wrong').status_code == 401
    assert rotate(client).status_code == 200
    assert push(client).status_code == 401
    assert push(client,secret='n'*32).status_code == 200
    assert register(client,secret='n'*32).status_code == 409
    # Idempotent recovery proves possession of the new current key.
    before = relay.extensions['relay_store'].endpoint('vpn.example.org')['rotated_at']
    assert rotate(client,old='n'*32).json['rotated_at'] == before


def test_keys_must_rotate_at_24_hours_without_extending_30_day_lifetime(tmp_path):
    relay = create_relay(str(tmp_path/'relay.sqlite'),'e'*32,'m'*32,Sender(),callback_sender=lambda *args: True)
    client = relay.test_client()
    now = time.time()
    with patch('time.time',return_value=now): assert register(client).status_code == 201
    with patch('time.time',return_value=now+86400):
        assert push(client).status_code == 409
        assert rotate(client).status_code == 200
        assert push(client,secret='n'*32).status_code == 200
    # Rotation is not a push and cannot keep an inactive endpoint alive forever.
    with patch('time.time',return_value=now+29*86400): assert rotate(client,old='n'*32,new='z'*32).status_code == 200
    with patch('time.time',return_value=now+32*86400):
        assert relay.extensions['relay_store'].summary() == []
        assert register(client,secret='x'*32).status_code == 201


def test_uploaded_custom_credentials_are_private_and_only_apple_urls_are_allowed(tmp_path):
    manager,settings = manager_for(tmp_path)
    upload,value = key_upload()
    manager.update_push({'push_choice':'custom','bundle_id':'org.example.custom','push_url':'https://api.push.apple.com'},settings,upload)
    assert settings.push_mode == 'direct'
    assert settings.apns_ready
    assert settings.apns_key_id == value['key_id']
    assert settings.apns_team_id == value['team_id']
    assert (tmp_path/'custom-apns.p8').stat().st_mode & 0o777 == 0o600
    assert value['private_key'] not in manager.path.read_text()
    assert manager.load().apns_key_id == value['key_id']
    with pytest.raises(ValueError): manager.update_push({'push_choice':'custom','push_url':'https://other-relay.example.org'},settings)
    invalid_upload = FileStorage(stream=io.BytesIO(b'bad key'),filename='key.json')
    with pytest.raises(ValueError): manager.read_credentials(invalid_upload)
    manager.update_push({'push_choice':'primary'},settings)
    assert settings.push_mode == 'relay'
    assert settings.relay_url == 'https://push.family-vpn.workers.dev'


def test_hosted_relay_is_guarded_and_no_saved_secrets_are_rendered(tmp_path):
    manager,settings = manager_for(tmp_path)
    settings.automatic = False
    app = create_app(settings)
    install_relay(app,manager,callback_sender=lambda *args: True)
    app.session_interface = IngressSessionInterface()
    app.wsgi_app = IngressMiddleware(app.wsgi_app)
    client = app.test_client()
    prefix = '/api/hassio_ingress/synthetic'
    def ingress(path,**kwargs):
        return client.get(prefix+path,base_url='http://localhost:8099',headers={'X-Ingress-Path':prefix},environ_overrides={'REMOTE_ADDR':'172.30.32.2'},**kwargs)
    try:
        assert client.post('/endpoints',base_url='http://localhost:8500',json={}).status_code == 404
        upload,value = key_upload()
        manager.update_host({'host_enabled':'true','proxy_token':'p'*32,'host_topic':'org.example.app','host_push_url':'https://api.push.apple.com'},settings,upload)
        assert client.post('/endpoints',base_url='http://localhost:8500',json={}).status_code == 401
        body = body_bytes({'server':'vpn.example.org','callback':'https://owner.example.org/relay-results','token':'t'*32,'limit':10})
        assert client.post('/endpoints',base_url='http://localhost:8500',data=body,headers={**signed_headers('t'*32,'/endpoints',body),'X-Relay-Proxy-Token':'p'*32}).status_code == 201
        assert client.post('/relay-operator',base_url='http://localhost:8500').status_code == 404
        page = ingress('/advanced').data
        for secret in (settings.host_proxy_token,settings.relay_secret,settings.admin_secret,settings.enrollment_secret,value['private_key']):
            assert secret.encode() not in page
        assert b'name="key_file"' not in page
        assert b'name="relay_callback"' not in page
        assert b'Force rotate key' in page
        assert manager.load().host_proxy_token == 'p'*32
        assert client.post('/endpoints',base_url='http://localhost:8500',json={},headers={'X-Relay-Proxy-Token':'wrong'}).status_code == 401
        settings.host_proxy_token = ''
        assert client.post('/endpoints',base_url='http://localhost:8500',json={}).status_code == 400
        assert (tmp_path/'host-apns.p8').stat().st_mode & 0o777 == 0o600
    finally: app.extensions['dispatcher'].close()


def test_rotation_client_recovers_lost_response_and_persists_key(tmp_path):
    manager,settings = manager_for(tmp_path/'owner')
    settings.relay_server = settings.relay_registered_server = 'vpn.example.org'
    settings.rest_url = 'https://owner.example.org/family-vpn'
    settings.relay_secret = manager.secret('relay-token','t'*32)
    relay = create_relay(str(tmp_path/'relay.sqlite'),'e'*32,'m'*32,Sender(),callback_sender=lambda *args: True)
    client = relay.test_client()
    assert register(client).status_code == 201
    sender = RelaySender(settings)
    sender.manager = manager
    settings.relay_rotated_at = time.time()
    lost = True
    def post(url,content,headers):
        nonlocal lost
        result = client.post('/rotate',data=content,headers=headers)
        if result.status_code == 200 and lost:
            lost = False
            raise httpx.ReadTimeout('lost rotation response')
        return httpx.Response(result.status_code,json=result.json)
    with patch('httpx.Client') as factory:
        factory.return_value.__enter__.return_value.post.side_effect = post
        assert not sender.rotate(force=True)
        assert (manager.data/'relay-pending-rotation.json').exists()
        assert settings.relay_secret == 't'*32
        assert sender.rotate()
    assert settings.relay_secret != 't'*32
    assert manager.load().relay_secret == settings.relay_secret
    assert not (manager.data/'relay-pending-rotation.json').exists()
    assert push(client,secret=settings.relay_secret).status_code == 200


def test_host_reuses_provider_token_until_refresh_or_upload(tmp_path):
    manager,settings = manager_for(tmp_path)
    upload,_ = key_upload()
    manager.update_host({'host_enabled':'true','proxy_token':'p'*32,'host_topic':'org.example.app','host_push_url':'https://api.push.apple.com'},settings,upload)
    sender = HostedSender(manager,settings)
    with patch('family_vpn.app.APNsSender.send',return_value='accepted'):
        sender.send('ab'*32)
        token = sender.sender.jwt
        sender.send('ab'*32)
        assert sender.sender.jwt == token
        with patch('time.time',return_value=time.time()+3001):
            sender.send('ab'*32)
            assert sender.sender.jwt != token


def test_expired_endpoint_clears_local_registration_and_pending_rotation(tmp_path):
    manager,settings = manager_for(tmp_path)
    settings.rest_url = 'https://owner.example.org/family-vpn'
    settings.relay_server = settings.relay_registered_server = 'vpn.example.org'
    sender = RelaySender(settings)
    sender.manager = manager
    with patch('httpx.Client') as client:
        client.return_value.__enter__.return_value.post.return_value = httpx.Response(404,json={'error':'endpoint_missing'})
        assert not sender.rotate(force=True)
    assert settings.relay_registered_server == ''
    assert manager.load().relay_registered_server == ''
    assert not (tmp_path/'relay-pending-rotation.json').exists()


def test_existing_relay_database_migrates_without_losing_registration(tmp_path):
    import base64
    import hashlib
    import sqlite3
    from cryptography.fernet import Fernet
    from family_vpn.relay_service import RelayStore
    path = tmp_path/'relay.sqlite'
    cipher = Fernet(base64.urlsafe_b64encode(hashlib.sha256(('m'*32).encode()).digest()))
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE endpoints(server TEXT PRIMARY KEY,callback TEXT NOT NULL,secret BLOB NOT NULL,quota INTEGER NOT NULL)')
        db.execute('INSERT INTO endpoints VALUES(?,?,?,?)',('vpn.example.org','https://owner.example.org/relay-results',cipher.encrypt(('t'*32).encode()),10))
    store = RelayStore(str(path),'m'*32)
    endpoint = store.endpoint('vpn.example.org')
    assert endpoint['secret'] == 't'*32
    assert endpoint['last_push'] > 0
    assert endpoint['rotated_at'] > 0


def test_hosting_can_be_enabled_without_worker_credential(tmp_path):
    manager, settings = manager_for(tmp_path)
    upload, _ = key_upload()
    manager.update_host({'host_enabled':'true'}, settings, upload)
    assert manager.load().host_enabled
    assert manager.load().host_proxy_token == ''
