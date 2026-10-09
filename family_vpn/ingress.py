"""Listener isolation: trust only the Supervisor ingress gateway socket peer."""
import re
from flask import request
from flask.sessions import SecureCookieSessionInterface

INGRESS_FLAG = "vpnweb.ingress"
# Fixed Supervisor ingress gateway identity; trusting a configurable client header
# here would allow callers on the external listener to impersonate Supervisor.
SUPERVISOR_GATEWAY = "172.30.32.2"  # noqa: S1313

class IngressMiddleware:
    def __init__(self, application): self.application = application
    def __call__(self, environ, start_response):
        environ["vpnweb.home_assistant"] = True
        port = environ.get("SERVER_PORT")
        path = environ.get("PATH_INFO", "/")
        if port == "8099":
            prefix = environ.get("HTTP_X_INGRESS_PATH", "")
            if environ.get("REMOTE_ADDR") != SUPERVISOR_GATEWAY or not re.fullmatch(r"/api/hassio_ingress/[A-Za-z0-9_-]+/?", prefix):
                return self.reject(start_response, "403 Forbidden")
            if path.startswith(prefix.rstrip("/") + "/"):
                path = path[len(prefix.rstrip("/")):]
                environ["PATH_INFO"] = path
            # REST credentials belong on the external listener; ingress exposes only UI.
            if path not in {"/", "/provisioning", "/administration", "/activity", "/administrator-password", "/vpn-provisioning", "/command", "/push", "/configuration", "/advanced", "/relay-register", "/relay-rotate", "/push-setup", "/relay-operator", "/policy-settings", "/health"} and not path.startswith("/static/"):
                return self.reject(start_response, "404 Not Found")
            environ["SCRIPT_NAME"] = prefix.rstrip("/")
            environ[INGRESS_FLAG] = True
        elif port == "8500":
            if path not in {"/health", "/registrations", "/status", "/api/devices", "/api/push", "/api/commands", "/commands", "/command-results", "/vpn-configuration", "/relay-results", "/endpoints", "/rotate", "/push"}:
                return self.reject(start_response, "404 Not Found")
            environ.pop(INGRESS_FLAG, None)
            environ["SCRIPT_NAME"] = ""
        else: return self.reject(start_response, "403 Forbidden")
        return self.application(environ, start_response)
    @staticmethod
    def reject(start_response, status):
        start_response(status, [("Content-Type", "text/plain"), ("Cache-Control", "no-store")])
        return [b"Request denied"]

class IngressSessionInterface(SecureCookieSessionInterface):
    def get_cookie_path(self, app):
        if request.environ.get(INGRESS_FLAG): return request.script_root + "/"
        return super().get_cookie_path(app)
    def get_cookie_secure(self, app):
        if request.environ.get(INGRESS_FLAG):
            return request.environ.get("HTTP_X_FORWARDED_PROTO") == "https"
        return super().get_cookie_secure(app)
