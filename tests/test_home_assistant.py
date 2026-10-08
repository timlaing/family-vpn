import json
import re
import tempfile
import pytest
from pathlib import Path

from family_vpn.addon import AddonConfiguration
from family_vpn.app import create_app
from family_vpn.ingress import IngressMiddleware, IngressSessionInterface

PREFIX = '/api/hassio_ingress/synthetic_token'

class TestHomeAssistant:
    def setup_method(self):
        self.directory = tempfile.TemporaryDirectory()
        self.options = {'admin_bearer':'a'*32,'registration_bearer':'e'*32, 'automatic':False}
        Path(self.directory.name, 'options.json').write_text(json.dumps(self.options))
        self.manager = AddonConfiguration(self.directory.name)
        self.settings = self.manager.load()
        self.settings.secure_cookie = False
        self.app = create_app(self.settings)
        self.app.extensions['addon_configuration'] = self.manager
        self.app.session_interface = IngressSessionInterface()
        self.app.wsgi_app = IngressMiddleware(self.app.wsgi_app)
        self.client = self.app.test_client()
    def teardown_method(self):
        self.app.extensions['dispatcher'].close()
        self.directory.cleanup()
    def ingress(self, path='/', method='get', **kwargs):
        return getattr(self.client, method)(PREFIX+path, base_url='http://localhost:8099',
            headers={'X-Ingress-Path':PREFIX}, environ_overrides={'REMOTE_ADDR':'172.30.32.2'}, **kwargs)
    def test_only_supervisor_peer_can_enter_and_headers_cannot_spoof_it(self):
        response = self.client.get('/', base_url='http://localhost:8099', headers={'X-Ingress-Path':PREFIX,'X-Forwarded-For':'172.30.32.2'})
        assert (response.status_code) == (403)
        assert (self.client.get('/', base_url='http://localhost:8099', environ_overrides={'REMOTE_ADDR': '172.30.32.2'}).status_code) == (403)
    def test_ingress_prefix_assets_forms_and_iframe_headers(self):
        response=self.ingress()
        assert (response.status_code) == (200)
        assert ((PREFIX + '/static/style.css').encode()) in (response.data)
        assert ((PREFIX + '/push').encode()) in (response.data)
        assert ('X-Frame-Options') not in (response.headers)
        assert ("frame-ancestors 'self'") in (response.headers['Content-Security-Policy'])
        with self.ingress('/static/style.css') as asset: assert (asset.status_code) == (200)
        assert ('Path=' + PREFIX + '/') in (response.headers['Set-Cookie'])
        assert (self.ingress('/registrations', method='post', json={}).status_code) == (404)
    def test_external_listener_blocks_dashboard_and_keeps_rest_authentication(self):
        for path in ('/','/configuration','/login','/static/style.css','/push','/administrator-password'):
            assert (self.client.get(path, base_url='http://localhost:8081', headers={'X-Ingress-Path': PREFIX}).status_code) == (404)
        assert (self.client.get('/health', base_url='http://localhost:8081').status_code) == (200)
        assert (self.client.get('/api/devices', base_url='http://localhost:8081').status_code) == (401)
        assert (self.client.post('/registrations', base_url='http://localhost:8081', json={}).status_code) == (401)
        assert (self.client.get('/health', base_url='http://localhost:9999').status_code) == (403)
    def test_configuration_requires_csrf_and_persists_only_allowed_fields(self):
        response=self.ingress('/configuration')
        csrf=re.search(rb'name="csrf" value="([^"]+)"',response.data).group(1).decode()
        form={'csrf':csrf,'apns_key_id':'synthetic','apns_team_id':'synthetic','apns_topic':'uk.co.laingcorp.myvpn','apns_key_file':'/share/family-vpn/apns.p8','apns_environment':'sandbox','interval':'1800'}
        assert (self.ingress('/configuration', method='post', data={**form, 'csrf': 'wrong'}).status_code) == (403)
        assert (self.ingress('/configuration', method='post', data=form).status_code) == (302)
        values=json.loads(self.manager.path.read_text())
        assert ('admin_bearer') not in (values)
        assert ('registration_bearer') not in (values)
        assert (self.manager.load().interval) == (1800)
        assert (self.manager.path.stat().st_mode & 511) == (384)
        assert (self.settings.interval) == (1800)
        assert not (self.settings.automatic)
        for field,value in [('interval','10'),('apns_key_file','/share/../etc/passwd'),('apns_key_id','bad\nvalue')]:
            assert (self.ingress('/configuration', method='post', data={**form, field: value}).status_code) == (200)
            assert (self.manager.load().interval) == (1800)
    def test_session_secret_persists_and_reset_restores_options_after_restart(self):
        assert (self.manager.load().session_secret) == (self.settings.session_secret)
        assert (Path(self.directory.name, 'session-secret').stat().st_mode & 511) == (384)
        self.manager.update({'apns_key_id':'','apns_team_id':'','apns_topic':'test','apns_key_file':'','apns_environment':'sandbox','interval':'1800'},self.settings)
        self.manager.update({'reset':'true'},self.settings)
        assert (self.manager.load().interval) == (2700)
        assert not (self.manager.path.exists())

    def test_administrator_setup_is_ingress_only_on_addon_listeners(self):
        response=self.ingress()
        csrf=re.search(rb'name="csrf" value="([^"]+)"',response.data).group(1).decode()
        form={'csrf':csrf,'password':'dashboard-test-password','confirmation':'dashboard-test-password'}
        assert (self.ingress('/administrator-password', method='post', data=form).status_code) == (302)
        assert self.app.extensions['administrator'].configured()
        assert (self.client.post('/administrator-password', base_url='http://localhost:8081', data=form).status_code) == (404)
        assert (self.ingress('/administrator-password', method='post', data={**form, 'csrf': 'wrong'}).status_code) == (403)
