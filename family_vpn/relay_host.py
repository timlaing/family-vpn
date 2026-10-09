"""Host relay APIs inside the add-on while isolating them from Ingress UI."""
import hmac
import threading
from flask import abort, request
from .app import APNsSender
from .relay_client import PushSender
from .relay_service import create_relay


class HostedSender:
    def __init__(self, manager, settings):
        self.manager, self.settings = manager, settings
        self.sender = None
        self.fingerprint = None
        self.lock = threading.Lock()

    def send(self, token, command=None):
        settings = self.manager.host_settings(self.settings)
        key = self.manager.data/'host-apns.p8'
        fingerprint = (settings.apns_key_id,settings.apns_team_id,settings.apns_topic,settings.apns_environment,key.stat().st_mtime_ns if key.exists() else None)
        with self.lock:
            if fingerprint != self.fingerprint:
                self.sender = APNsSender(settings)
                self.fingerprint = fingerprint
            sender = self.sender
            # Cache the provider JWT across requests; never issue one per push.
            if settings.apns_ready:
                try: sender.provider_jwt()
                except (ValueError,OSError,TypeError): return 'provider_error'
        return sender.send(token,command)


class RelayRouter:
    def __init__(self, dashboard, relay):
        self.dashboard, self.relay = dashboard, relay

    def __call__(self, environ, start_response):
        if environ.get('SERVER_PORT') == '8500' and environ.get('PATH_INFO') in {'/endpoints','/rotate','/push'}:
            return self.relay(environ,start_response)
        return self.dashboard(environ,start_response)


def install_relay(app, manager, callback_sender=None):
    settings = app.extensions['settings']
    app.extensions['addon_configuration'] = manager
    sender = app.extensions['dispatcher'].sender
    if isinstance(sender,PushSender): sender.relay.manager = manager

    def authorize():
        if not settings.host_enabled: abort(404)
        supplied = request.headers.get('X-Relay-Proxy-Token','')
        if not settings.host_proxy_token or not hmac.compare_digest(supplied.encode(),settings.host_proxy_token.encode()): abort(401)

    kwargs = {'callback_sender':callback_sender} if callback_sender else {}
    relay = create_relay(str(manager.data/'relay.sqlite'),manager.secret('relay-host-enrollment'),
        manager.secret('relay-storage-secret'),HostedSender(manager,settings),
        max_limit=lambda:settings.host_limit,authorize=authorize,**kwargs)
    app.extensions['hosted_relay'] = relay
    app.wsgi_app = RelayRouter(app.wsgi_app,relay.wsgi_app)

    def maintenance():
        relay.extensions['relay_store'].prune()
        if isinstance(sender,PushSender) and settings.push_mode == 'relay' and settings.apns_ready:
            sender.relay.rotate()

    app.extensions['dispatcher'].maintenance = maintenance
    return relay
