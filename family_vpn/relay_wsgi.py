"""Relay entrypoint for an HTTPS reverse proxy; separate from the HA dashboard."""
import os
from .app import Settings, APNsSender
from .relay_service import create_relay
settings = Settings.from_environment()
settings.push_mode = 'direct'
settings.apns_environment = os.getenv('APNS_ENVIRONMENT', 'production')
if not settings.apns_ready: raise ValueError('Configure the published app APNs provider on the relay')
application = create_relay(os.getenv('RELAY_DATABASE','/data/relay.sqlite'),
    os.environ['RELAY_ENROLLMENT_BEARER'], os.environ['RELAY_STORAGE_SECRET'], APNsSender(settings),
    max_limit=int(os.getenv('RELAY_MAX_PER_MINUTE','100')))
