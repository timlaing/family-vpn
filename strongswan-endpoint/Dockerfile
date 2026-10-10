FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    strongswan-charon strongswan-swanctl strongswan-pki \
    libstrongswan-standard-plugins libstrongswan-extra-plugins libcharon-extra-plugins libcharon-extauth-plugins \
    iptables iproute2 openssl python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY strongswan.conf /etc/strongswan.conf
COPY entrypoint.sh /usr/local/bin/vpn-entrypoint
COPY configure.py /usr/local/bin/configure-vpn
COPY swanctl.conf.template /usr/local/bin/swanctl.conf.template
RUN chmod 755 /usr/local/bin/vpn-entrypoint /usr/local/bin/configure-vpn
EXPOSE 500/udp 4500/udp
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD swanctl --list-conns | grep -q 'family-vpn:'
ENTRYPOINT ["/usr/local/bin/vpn-entrypoint"]
