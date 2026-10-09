import os
from .app import create_app

if os.getenv("VPNWEB_HOME_ASSISTANT") == "true":
    from .addon import AddonConfiguration
    from .ingress import IngressMiddleware, IngressSessionInterface
    configuration = AddonConfiguration()
    application = create_app(configuration.load())
    from .relay_host import install_relay
    install_relay(application, configuration)
    application.config["SESSION_COOKIE_NAME"] = "family_vpn_session"
    application.session_interface = IngressSessionInterface()
    application.wsgi_app = IngressMiddleware(application.wsgi_app)
else:
    application = create_app()
