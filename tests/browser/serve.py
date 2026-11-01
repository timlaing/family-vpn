"""Run an isolated, read-only dashboard for browser tests."""
import sys
import tempfile
from pathlib import Path

from werkzeug.serving import make_server

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from family_vpn.app import Settings, create_app, seed_demo

with tempfile.TemporaryDirectory(prefix="family-vpn-browser-") as directory:
    app = create_app(Settings(database=f"{directory}/demo.sqlite", demo=True,
                              automatic=False, secure_cookie=False))
    seed_demo(app)
    try:
        with make_server("127.0.0.1", 18500, app, threaded=True) as server:
            server.serve_forever()
    finally:
        app.extensions["dispatcher"].close()
