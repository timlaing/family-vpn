"""Validate and render the endpoint's local or external RADIUS authentication."""
import ipaddress
import json
from pathlib import Path
import re


def atomic(path, contents, owner=None):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(contents)
    temporary.chmod(0o600)
    if owner is not None:
        import os
        os.chown(temporary, owner, owner)
    temporary.replace(path)


def read_settings(data):
    path = Path(data) / "authentication/settings.json"
    return json.loads(path.read_text()) if path.exists() else {"mode": "local"}


def server_address(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ValueError:
        if not value or len(value) > 253 or any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in value.split(".")
        ):
            raise ValueError("Use a RADIUS IPv4 address or DNS hostname, without URL or port") from None
        return value


def port_number(value):
    try:
        number = int(value)
    except (ValueError, TypeError):
        raise ValueError("RADIUS ports must be numbers between 1 and 65535") from None
    if not 1 <= number <= 65535:
        raise ValueError("RADIUS ports must be numbers between 1 and 65535")
    return number


def radius_settings(previous, server, secret, auth_port, acct_port, nas_identifier, accounting):
    secret = secret or previous.get("secret", "")
    if not 16 <= len(secret) <= 256 or any(ord(c) < 32 or ord(c) > 126 or c in {'"', chr(92)} for c in secret):
        raise ValueError("Use a 16–256 character printable RADIUS secret without quotes or backslashes")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", nas_identifier):
        raise ValueError("Use a simple NAS identifier of up to 64 characters")
    return {"mode": "radius", "server": server_address(server), "secret": secret,
            "auth_port": port_number(auth_port), "acct_port": port_number(acct_port),
            "nas_identifier": nas_identifier, "accounting": bool(accounting)}


def configure_authentication(data, mode, server="", secret="", auth_port=1812, acct_port=1813,
                             nas_identifier="family-vpn", accounting=False):
    data = Path(data)
    previous = read_settings(data)
    if mode == "radius":
        settings = radius_settings(previous, server, secret, auth_port, acct_port, nas_identifier, accounting)
    elif mode == "local":
        settings = dict(previous, mode="local")
    else:
        raise ValueError("Choose local accounts or an external RADIUS server")
    # Validate everything before changing the gateway's authentication files.
    folder = data / "authentication"
    folder.mkdir(mode=0o700, exist_ok=True)
    connection = data / "swanctl/swanctl.conf"
    contents = connection.read_text().replace("auth = eap-radius", "auth = eap-mschapv2")
    radius_file = folder / "radius.conf"
    if mode == "radius":
        contents = contents.replace("auth = eap-mschapv2", "auth = eap-radius")
        plugin = ('charon {\n  plugins {\n    eap-radius {\n      load = yes\n'
                  f'      accounting = {"yes" if settings["accounting"] else "no"}\n'
                  '      servers {\n        family-vpn {\n'
                  f'          address = "{settings["server"]}"\n'
                  f'          auth_port = {settings["auth_port"]}\n'
                  f'          acct_port = {settings["acct_port"]}\n'
                  f'          nas_identifier = "{settings["nas_identifier"]}"\n'
                  f'          secret = "{settings["secret"]}"\n'
                  '        }\n      }\n    }\n  }\n}\n')
        atomic(radius_file, plugin)
    else:
        radius_file.unlink(missing_ok=True)
    atomic(connection, contents)
    atomic(folder / "settings.json", json.dumps(settings))
    return settings


def public_settings(data):
    settings = read_settings(data)
    return {key: value for key, value in settings.items() if key != "secret"} | {"has_secret": bool(settings.get("secret"))}
