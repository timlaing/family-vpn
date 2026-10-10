"""Guided setup, isolated UI and transactional one-use enrollment."""
import base64
from concurrent.futures import ThreadPoolExecutor
import json
import re
import time
import uuid
from unittest.mock import patch
import pytest
from family_vpn.addon import AddonConfiguration
from family_vpn.app import create_app
from family_vpn.ingress import IngressMiddleware, IngressSessionInterface
from family_vpn.relay_host import install_relay

PREFIX = '/api/hassio_ingress/test'

@pytest.fixture
def dashboard(tmp_path):
    (tmp_path/'options.json').write_text('{"automatic":false}')
    manager=AddonConfiguration(tmp_path)
    settings=manager.load()
    settings.secure_cookie=False
    app=create_app(settings)
    install_relay(app,manager,callback_sender=lambda *args: True)
    app.session_interface=IngressSessionInterface()
    app.wsgi_app=IngressMiddleware(app.wsgi_app)
    yield app,settings
    app.extensions['dispatcher'].close()


def ingress(client,path,method='get',**kwargs):
    return getattr(client,method)(PREFIX+path,base_url='http://localhost:8099',headers={'X-Ingress-Path':PREFIX},environ_overrides={'REMOTE_ADDR':'172.30.32.2'},**kwargs)


def ready(app,settings):
    app.extensions['vpn_provisioning'].save('vpn.example.org','',[])
    app.extensions['administrator'].set_password('synthetic-password','synthetic-password')
    settings.rest_url='https://dashboard.example.org/family-vpn'
    settings.relay_server=settings.relay_registered_server='vpn.example.org'


def invitation(app):
    return app.extensions['enrollment'].issue('https://dashboard.example.org/family-vpn/registrations')


def token_for(invite):
    payload=invite['link'].split('#')[1]
    return json.loads(base64.urlsafe_b64decode(payload+'='*((4-len(payload)%4)%4)))['token']


def register(app,token,device=None):
    return app.test_client().post('/registrations',base_url='http://localhost:8500',headers={
        'Authorization':'Bearer '+token,'X-FamilyVPN-Command-Protocol':'1',
        'X-FamilyVPN-Administrator-Protocol':'1','X-FamilyVPN-VPN-Protocol':'2'},json={'id':device or str(uuid.uuid4()),'token':'ab'*32})


def test_single_use_invite_issues_device_scoped_credential(dashboard):
    app,settings=dashboard
    ready(app,settings)
    invite=invitation(app)
    token=token_for(invite)
    device=str(uuid.uuid4())
    response=register(app,token,device)
    assert response.status_code==201
    credential=response.json['enrollment_token']
    assert credential.startswith('device_')
    assert register(app,token,device).status_code==401
    assert register(app,credential,device).status_code==201
    assert register(app,credential).status_code==401
    with app.extensions['database'].connect() as db:
        assert not db.execute('SELECT * FROM enrollment_invites').fetchall()
        stored=dict(db.execute('SELECT * FROM devices WHERE id=?',(device,)).fetchone())
    assert credential not in json.dumps(stored)
    assert token not in json.dumps(stored)


def test_invites_expire_replace_and_roll_back_on_invalid_registration(dashboard):
    app,settings=dashboard
    ready(app,settings)
    old=token_for(invitation(app))
    current=token_for(invitation(app))
    assert register(app,old).status_code==401
    assert app.test_client().post('/registrations',base_url='http://localhost:8500',headers={'Authorization':'Bearer '+current},json={'id':str(uuid.uuid4()),'token':'ab'*32}).status_code==400
    assert register(app,current).status_code==201
    expired=token_for(invitation(app))
    with app.extensions['database'].connect() as db:
        db.execute('UPDATE enrollment_invites SET expires=?',(time.time()-1,))
    assert register(app,expired).status_code==401


def test_concurrent_redemption_has_exactly_one_winner(dashboard):
    app,settings=dashboard
    ready(app,settings)
    token=token_for(invitation(app))
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda _:register(app,token).status_code,range(2)))
    assert sorted(responses)==[201,401]


def test_setup_and_invitation_ui_are_ingress_only_and_csrf_protected(dashboard):
    app,settings=dashboard
    client=app.test_client()
    assert ingress(client,'/').location.endswith('/setup')
    page=ingress(client,'/setup')
    assert b'Save and continue' in page.data
    assert b'provisioning.js' in page.data
    assert ingress(client,'/add-device').location.endswith('/setup')
    for path in ('/setup','/add-device'):
        assert client.get(path,base_url='http://localhost:8500').status_code==404
    ready(app,settings)
    page=ingress(client,'/add-device')
    csrf=re.search(rb'name="csrf" value="([^"]+)"',page.data).group(1).decode()
    assert ingress(client,'/add-device','post').status_code==403
    page=ingress(client,'/add-device','post',data={'csrf':csrf})
    assert page.status_code==200 and b'<svg' in page.data and b'familyvpn://enroll#' in page.data
    assert page.headers['Cache-Control']=='no-store'
    for secret in (settings.enrollment_secret,settings.admin_secret,settings.relay_secret):
        assert secret.encode() not in page.data


def test_proxy_generation_preserves_lan_vpn_and_public_route_boundaries(dashboard):
    app,settings=dashboard
    ready(app,settings)
    client=app.test_client()
    page=ingress(client,'/setup')
    # Existing users may revisit the guide after setup to regenerate proxy config.
    csrf=re.search(rb'name="csrf" value="([^"]+)"',ingress(client,'/add-device').data).group(1).decode()
    page=ingress(client,'/setup','post',data={'csrf':csrf,'action':'proxy','upstream':'192.168.1.20','vpn_networks':'10.20.30.0/24','registration_networks':'192.168.10.0/24'})
    assert page.status_code==200
    assert b'allow 192.168.10.0/24;' in page.data
    assert b'allow 10.20.30.0/24;' in page.data
    assert b'/family-vpn/setup-probe' in page.data
    assert b'proxy_set_header Authorization' in page.data


def test_https_probe_is_one_use_and_checks_own_installation(dashboard):
    app,settings=dashboard
    ready(app,settings)
    settings.relay_registered_server=''
    client=app.test_client()
    csrf=re.search(rb'name="csrf" value="([^"]+)"',ingress(client,'/setup').data).group(1).decode()
    class Probe:
        def __init__(self,*args,**kwargs): pass
        def request(self,method,path,body,headers):
            assert path=='/family-vpn/setup-probe'
            self.response=app.test_client().post('/setup-probe',base_url='http://localhost:8500',headers=headers,data=body)
            assert app.test_client().post('/setup-probe',base_url='http://localhost:8500',headers=headers,data=body).status_code==401
        def getresponse(self):
            self.status=self.response.status_code
            return self
        def read(self,limit): return self.response.data[:limit]
        def close(self): pass
    with patch('family_vpn.setup.PublicHTTPS',Probe):
        page=ingress(client,'/setup','post',data={'csrf':csrf,'action':'check'})
    assert b'HTTPS and dashboard routing verified' in page.data
    assert client.post('/setup-probe',base_url='http://localhost:8500',json={}).status_code==401
    assert ingress(client,'/setup-probe','post',data={'csrf':csrf}).status_code==404
    with app.extensions['database'].connect() as db:
        assert not db.execute('SELECT * FROM setup_probes').fetchall()


def test_one_button_verifies_https_and_registers_primary_relay(dashboard):
    app,settings=dashboard
    ready(app,settings)
    settings.relay_registered_server=''
    client=app.test_client()
    csrf=re.search(rb'name="csrf" value="([^"]+)"',ingress(client,'/setup').data).group(1).decode()
    with patch('family_vpn.setup.SetupViews.check_connection') as check, patch.object(app.extensions['dispatcher'].sender.relay,'register',return_value='registered') as register_endpoint:
        response=ingress(client,'/setup','post',data={'csrf':csrf,'action':'enable'})
    assert response.status_code==302 and response.location.endswith('/add-device')
    check.assert_called_once()
    register_endpoint.assert_called_once()
    assert settings.relay_registered_server==settings.relay_server


def test_failed_connectivity_does_not_register_endpoint(dashboard):
    app,settings=dashboard
    ready(app,settings)
    settings.relay_registered_server=''
    client=app.test_client()
    csrf=re.search(rb'name="csrf" value="([^"]+)"',ingress(client,'/setup').data).group(1).decode()
    with patch('family_vpn.setup.SetupViews.check_connection',side_effect=ValueError('Check your HTTPS address')), patch.object(app.extensions['dispatcher'].sender.relay,'register') as register_endpoint:
        response=ingress(client,'/setup','post',data={'csrf':csrf,'action':'enable'})
    assert b'Check your HTTPS address' in response.data
    register_endpoint.assert_not_called()
    assert not settings.relay_registered_server


def test_foreign_server_cannot_fake_connectivity_with_a_generic_ok_response(dashboard):
    app,settings=dashboard
    ready(app,settings)
    settings.relay_registered_server=''
    client=app.test_client()
    csrf=re.search(rb'name="csrf" value="([^"]+)"',ingress(client,'/setup').data).group(1).decode()
    class Foreign:
        status=200
        def __init__(self,*args,**kwargs): pass
        def request(self,*args): pass
        def getresponse(self): return self
        def read(self,limit): return b'{"status":"ok"}\n'
        def close(self): pass
    with patch('family_vpn.setup.PublicHTTPS',Foreign):
        response=ingress(client,'/setup','post',data={'csrf':csrf,'action':'check'})
    assert b'Cannot verify the public dashboard address' in response.data
    assert b'HTTPS and dashboard routing verified' not in response.data
