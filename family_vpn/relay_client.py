"""Forward transient device push data to an endpoint-authenticated relay."""
import httpx
import json
import secrets
import threading
import time
from urllib.parse import urlsplit
from .relay_protocol import body_bytes, https_url, signed_headers


class RelaySender:
    def __init__(self, settings):
        self.settings = settings
        self.last_result = 'not_contacted'
        self.manager = None
        self.lock = threading.RLock()

    def register(self):
        settings = self.settings
        url = https_url(settings.relay_url)+'/endpoints'
        body = {'server':settings.relay_server, 'callback':https_url(settings.callback_url),
                'token':settings.relay_secret, 'limit':settings.relay_limit}
        try:
            with httpx.Client(timeout=15, follow_redirects=False) as client:
                encoded = body_bytes(body)
                headers = signed_headers(settings.relay_secret, urlsplit(url).path, encoded)
                if settings.relay_enrollment: headers['Authorization'] = 'Bearer '+settings.relay_enrollment
                response = client.post(url, headers=headers, content=encoded)
            self.last_result = 'registered' if response.status_code == 201 else 'endpoint_exists' if response.status_code == 409 else 'registration_failed'
            if response.status_code == 201:
                settings.relay_rotated_at = time.time()
                if self.manager: self.manager.save_settings(settings)
        except httpx.RequestError:
            self.last_result = 'network_error'
        return self.last_result

    def rotate(self, force=False):
        with self.lock:
            settings = self.settings
            pending_file = self.manager.data/'relay-pending-rotation.json' if self.manager else None
            if not force and time.time()-settings.relay_rotated_at < 86400 and not (pending_file and pending_file.exists()):
                return True
            if pending_file and pending_file.exists():
                pending = json.loads(pending_file.read_text())
                if pending['server'] != settings.relay_server or pending['url'] != settings.relay_url:
                    self.last_result = 'rotation_pending_for_previous_endpoint'
                    return False
            else:
                pending = {'server':settings.relay_server,'url':settings.relay_url,'token':secrets.token_urlsafe(32)}
                if self.manager: self.manager.private_file('relay-pending-rotation.json',json.dumps(pending))
            url = https_url(settings.relay_url)+'/rotate'
            body = body_bytes({'server':settings.relay_server,'token':pending['token'],'callback':settings.callback_url})
            try:
                with httpx.Client(timeout=15,follow_redirects=False) as client:
                    # Probe the pending key first to recover an accepted rotation with a lost response.
                    response = client.post(url,content=body,headers=signed_headers(pending['token'],'/rotate',body))
                    if response.status_code == 401:
                        response = client.post(url,content=body,headers=signed_headers(settings.relay_secret,'/rotate',body))
                if response.status_code != 200:
                    self.last_result = 'endpoint_missing' if response.status_code == 404 else 'rotation_failed'
                    if response.status_code == 404:
                        settings.relay_registered_server = ''
                        if self.manager:
                            self.manager.save_settings(settings)
                            pending_file.unlink(missing_ok=True)
                    return False
                rotated_at = response.json()['rotated_at']
                if not isinstance(rotated_at,(int,float)) or not 0 <= rotated_at <= time.time()+300: raise ValueError()
                if self.manager: self.manager.secret('relay-token',pending['token'])
                settings.relay_secret = pending['token']
                settings.relay_rotated_at = rotated_at
                if self.manager:
                    self.manager.save_settings(settings)
                    pending_file.unlink(missing_ok=True)
                self.last_result = 'key_rotated'
                return True
            except (httpx.RequestError,ValueError,KeyError):
                self.last_result = 'rotation_failed'
                return False

    def send(self, token, command=None, device=None):
        with self.lock: return self._send(token,command,device)

    def _send(self, token, command=None, device=None):
        if not self.settings.apns_ready: return 'not_configured'
        if not self.rotate(): return 'retry_later'
        url = https_url(self.settings.relay_url)+'/push'
        body = body_bytes({'server':self.settings.relay_server, 'device':device, 'token':token, 'command':command})
        try:
            with httpx.Client(timeout=25, follow_redirects=False) as client:
                response = client.post(url, content=body, headers=signed_headers(self.settings.relay_secret, urlsplit(url).path, body))
            if response.status_code == 429: self.last_result = 'retry_later'
            elif response.status_code == 200:
                result = response.json().get('result')
                self.last_result = result if result in {'accepted','invalid_token','retry_later','network_error','provider_error'} else 'provider_error'
            else: self.last_result = 'relay_error'
        except (httpx.RequestError, ValueError, AttributeError):
            self.last_result = 'network_error'
        return self.last_result


class PushSender:
    """Select the current transport without requiring a restart."""
    def __init__(self, settings):
        from .app import APNsSender
        self.settings = settings
        self.direct = APNsSender(settings)
        self.relay = RelaySender(settings)

    def send(self, token, command=None, device=None):
        if self.settings.push_mode == 'relay': return self.relay.send(token, command, device)
        return self.direct.send(token, command)
