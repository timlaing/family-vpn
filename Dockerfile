FROM python:3.14-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 VPNWEB_DATABASE=/data/vpnweb.sqlite
WORKDIR /app
COPY requirements.lock ./
RUN python -m pip install --no-cache-dir --only-binary=:all: --no-deps --require-hashes -r requirements.lock \
    && python -m pip check \
    && groupadd --gid 10001 vpnweb \
    && useradd --uid 10001 --gid vpnweb --no-create-home vpnweb \
    && mkdir /data && chown vpnweb:vpnweb /data
COPY family_vpn ./family_vpn
USER 10001:10001
EXPOSE 8081
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/health', timeout=3).close()"
CMD ["gunicorn", "--workers", "1", "--threads", "4", "--bind", "0.0.0.0:8081", "--access-logfile", "/dev/null", "--error-logfile", "-", "family_vpn.wsgi:application"]
