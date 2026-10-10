"""Guided Ingress setup, proxy generation and one-time device enrollment."""
import http.client
import secrets
import time
from urllib.parse import urlsplit
from flask import make_response, abort, jsonify, redirect, render_template, request, url_for
from .enrollment import token_hash
from .proxy import generate
from .relay_service import PublicHTTPS


class SetupViews:
    def __init__(self, app, views):
        self.app, self.views = app, views
        for path, endpoint, handler, methods in (
            ('/setup','setup',self.setup,['GET','POST']),
            ('/add-device','add_device',self.add_device,['GET','POST']),
            ('/setup-probe','setup_probe',self.probe,['POST']),
        ):
            app.add_url_rule(path,endpoint=endpoint,view_func=handler,methods=methods)
        with views.database.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS setup_probes (hash TEXT PRIMARY KEY, expires REAL NOT NULL, verified INTEGER NOT NULL DEFAULT 0)')
            if 'verified' not in {row['name'] for row in db.execute('PRAGMA table_info(setup_probes)')}:
                db.execute('ALTER TABLE setup_probes ADD COLUMN verified INTEGER NOT NULL DEFAULT 0')

    def step(self):
        views = self.views
        if not views.vpn_provisioning.enrollment() or not views.settings.rest_url: return 'network'
        if not views.administrator.configured(): return 'administrator'
        if not views.settings.apns_ready: return 'connection'
        return 'devices'

    def check_connection(self):
        settings = self.views.settings
        parsed = urlsplit(settings.rest_url)
        token = secrets.token_urlsafe(32)
        with self.views.database.connect() as db:
            db.execute('DELETE FROM setup_probes WHERE expires<=?', (time.time(),))
            db.execute('INSERT INTO setup_probes(hash,expires) VALUES(?,?)',(token_hash(token),time.time()+60))
        connection = PublicHTTPS(parsed.hostname,timeout=5)
        try:
            connection.request('POST',parsed.path.rstrip('/')+'/setup-probe',b'{}',{'Authorization':'Bearer '+token,'Content-Type':'application/json'})
            response = connection.getresponse()
            if response.status != 200 or response.read(128) != b'{"status":"ok"}\n':
                raise ValueError('The public dashboard address did not reach this installation. Check DNS, HTTPS and the generated proxy locations.')
            with self.views.database.connect() as db:
                confirmed = db.execute('SELECT verified FROM setup_probes WHERE hash=? AND expires>?',(token_hash(token),time.time())).fetchone()
                if not confirmed or not confirmed['verified']: raise ValueError('HTTPS reached a different installation')
        except (OSError, ValueError, http.client.HTTPException) as exc:
            raise ValueError('Cannot verify the public dashboard address. Check DNS, HTTPS and the generated proxy locations.') from exc
        finally:
            connection.close()
            with self.views.database.connect() as db:
                db.execute('DELETE FROM setup_probes WHERE hash=?',(token_hash(token),))

    def probe(self):
        bearer = self.views.bearer()
        if not bearer: abort(401)
        with self.views.database.connect() as db:
            result = db.execute('UPDATE setup_probes SET verified=1 WHERE hash=? AND expires>? AND verified=0',(token_hash(bearer),time.time()))
            if not result.rowcount: abort(401)
        return jsonify(status='ok')

    def setup(self):
        manager = self.views.addon_manager()
        error, config, success = None, None, False
        if request.method == 'POST':
            action = request.form.get('action')
            try:
                if action == 'proxy':
                    if self.step() in {'network','administrator'}: abort(409)
                    parsed = urlsplit(self.views.settings.rest_url)
                    config = generate(request.form.get('upstream',''),int(request.form.get('port','8500')),parsed.path.rstrip('/')+'/',
                        request.form.get('vpn_networks','').split(),True,request.form.get('registration_networks','').split(),self.views.settings.host_enabled)
                elif action in {'check','enable'}:
                    if self.step() in {'network','administrator'}: abort(409)
                    self.check_connection()
                    if action == 'enable':
                        if self.views.settings.push_choice == 'primary':
                            manager.update_push({'push_choice':'primary'},self.views.settings)
                            if not self.views.settings.apns_ready:
                                response = make_response(self.views.relay_register())
                                if response.status_code == 302: return redirect(url_for('add_device'))
                                raise ValueError(response.get_data(as_text=True))
                        elif not self.views.settings.apns_ready: return redirect(url_for('advanced'))
                        return redirect(url_for('add_device'))
                    success = True
                else: abort(400)
            except (ValueError,TypeError) as exc: error = str(exc)
        return render_template('setup.html',step='connection' if config or (self.step() == 'devices' and request.args.get('step') == 'connection') else self.step(),settings=self.views.settings,error=error,proxy_config=config,checked=success,
            vpn_provision=self.views.vpn_provisioning.enrollment(),administrator_configured=self.views.administrator.configured())

    def add_device(self):
        self.views.addon_manager()
        if self.step() != 'devices': return redirect(url_for('setup'))
        invitation = None
        if request.method == 'POST':
            invitation = self.app.extensions['enrollment'].issue(self.views.settings.rest_url.rstrip('/')+'/registrations')
        return render_template('add_device.html',invitation=invitation)
