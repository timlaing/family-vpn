"""Forward transient device push data to an endpoint-authenticated relay."""
import httpx
from urllib.parse import urlsplit
from .relay_protocol import body_bytes, https_url, signed_headers


class RelaySender:
    def __init__(self, settings):
        self.settings = settings
        self.last_result = 'not_contacted'

    def register(self):
        settings = self.settings
        url = https_url(settings.relay_url)+'/endpoints'
        body = {'server':settings.relay_server, 'callback':https_url(settings.relay_callback),
                'token':settings.relay_secret, 'limit':settings.relay_limit}
        try:
            with httpx.Client(timeout=15, follow_redirects=False) as client:
                encoded = body_bytes(body)
                headers = signed_headers(settings.relay_secret, urlsplit(url).path, encoded)
                headers['Authorization'] = 'Bearer '+settings.relay_enrollment
                response = client.post(url, headers=headers, content=encoded)
            self.last_result = 'registered' if response.status_code == 201 else 'registration_failed'
        except httpx.RequestError:
            self.last_result = 'network_error'
        return self.last_result

    def send(self, token, command=None, device=None):
        if not self.settings.apns_ready: return 'not_configured'
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
