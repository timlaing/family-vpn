FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VPNWEB_DATABASE=/data/vpnweb.sqlite
WORKDIR /app
ARG BUILD_VERSION=0.3.0
ARG BUILD_ARCH=amd64
LABEL io.hass.type="app" io.hass.version=$BUILD_VERSION io.hass.arch=$BUILD_ARCH
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r requirements.lock \
    && python -m pip check \
    && groupadd --gid 10001 vpnweb \
    && useradd --uid 10001 --gid vpnweb --no-create-home vpnweb \
    && mkdir /data && chown vpnweb:vpnweb /data
COPY __init__.py addon.py administrator.py app.py commands.py ingress.py provisioning.py wsgi.py ./family_vpn/
COPY templates/ ./family_vpn/templates/
COPY static/ ./family_vpn/static/
ENV VPNWEB_HOME_ASSISTANT=true
EXPOSE 8081 8099
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=3).close()"
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8081", "--bind", "0.0.0.0:8099", "--access-logfile", "/dev/null", "--error-logfile", "-", "family_vpn.wsgi:application"]
