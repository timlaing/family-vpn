"""Forward transient device push data to an endpoint-authenticated relay."""
import httpx
import json
import secrets
import threading
import time
from urllib.parse import urlsplit
from .relay_protocol import body_bytes, https_url, signed_headers


ROTATE_PATH = "/rotate"


class RelaySender:
    def __init__(self, settings):
        self.settings = settings
        self.last_result = 'not_contacted'
        self.probe = None
        self.ping_at = 0
        self.callback_at = 0
        self.connectivity = 'Not checked'
        self.manager = None
        self.lock = threading.RLock()

    def ping(self):
        import uuid
        self.probe = str(uuid.uuid4())
        self.ping_at = time.time()
        self.callback_at = 0
        body = body_bytes({'server':self.settings.relay_server,'probe':self.probe})
        try:
            with httpx.Client(timeout=25,follow_redirects=False) as client:
                response = client.post(https_url(self.settings.relay_url)+'/ping',content=body,
                    headers=signed_headers(self.settings.relay_secret,'/ping',body))
            if response.status_code != 200:
                self.connectivity = 'Relay rejected the check'
            else:
                self.connectivity = 'Reachable · callback verified' if self.callback_at else 'Reachable · callback failed'
        except (httpx.RequestError,ValueError):
            self.connectivity = 'Unable to reach relay'
        finally:
            self.probe = None
        return self.connectivity

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
            self.last_result = {201: 'registered', 409: 'endpoint_exists'}.get(response.status_code, 'registration_failed')
            if response.status_code == 201:
                settings.relay_rotated_at = time.time()
                if self.manager: self.manager.save_settings(settings)
        except httpx.RequestError:
            self.last_result = 'network_error'
        return self.last_result

    def pending_rotation(self, pending_file):
        settings = self.settings
        if pending_file and pending_file.exists():
            pending = json.loads(pending_file.read_text())
            if pending['server'] != settings.relay_server or pending['url'] != settings.relay_url:
                self.last_result = 'rotation_pending_for_previous_endpoint'
                return None
            return pending
        pending = {'server':settings.relay_server,'url':settings.relay_url,'token':secrets.token_urlsafe(32)}
        if self.manager: self.manager.private_file('relay-pending-rotation.json',json.dumps(pending))
        return pending

    def request_rotation(self, pending):
        settings = self.settings
        url = https_url(settings.relay_url)+ROTATE_PATH
        body = body_bytes({'server':settings.relay_server,'token':pending['token'],'callback':settings.callback_url})
        with httpx.Client(timeout=15,follow_redirects=False) as client:
            # Probe the pending key first to recover an accepted rotation with a lost response.
            response = client.post(url,content=body,headers=signed_headers(pending['token'],ROTATE_PATH,body))
            if response.status_code == 401:
                response = client.post(url,content=body,headers=signed_headers(settings.relay_secret,ROTATE_PATH,body))
        return response

    def rotation_failed(self, response, pending_file):
        self.last_result = 'endpoint_missing' if response.status_code == 404 else 'rotation_failed'
        if response.status_code == 404:
            self.settings.relay_registered_server = ''
            if self.manager:
                self.manager.save_settings(self.settings)
                pending_file.unlink(missing_ok=True)
        return False

    def finish_rotation(self, response, pending, pending_file):
        rotated_at = response.json()['rotated_at']
        if not isinstance(rotated_at,(int,float)) or not 0 <= rotated_at <= time.time()+300: raise ValueError()
        if self.manager: self.manager.secret('relay-token',pending['token'])
        self.settings.relay_secret = pending['token']
        self.settings.relay_rotated_at = rotated_at
        if self.manager:
            self.manager.save_settings(self.settings)
            pending_file.unlink(missing_ok=True)
        self.last_result = 'key_rotated'
        return True

    def rotate(self, force=False):
        with self.lock:
            pending_file = self.manager.data/'relay-pending-rotation.json' if self.manager else None
            if not force and time.time()-self.settings.relay_rotated_at < 86400 and not (pending_file and pending_file.exists()):
                return True
            pending = self.pending_rotation(pending_file)
            if pending is None: return False
            try:
                response = self.request_rotation(pending)
                if response.status_code != 200: return self.rotation_failed(response, pending_file)
                return self.finish_rotation(response, pending, pending_file)
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
