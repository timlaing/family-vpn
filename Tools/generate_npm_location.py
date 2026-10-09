#!/usr/bin/env python3
"""Generate a complete Nginx location; never apply changes to a running proxy."""
import argparse
import ipaddress
import re


def validated_networks(values, purpose):
    networks = [ipaddress.ip_network(value, strict=False) for value in values]
    if not networks or any(value.prefixlen == 0 or value.is_multicast or value.is_unspecified for value in networks):
        raise ValueError(f'Supply explicit {purpose} source networks; default routes are forbidden')
    return networks


def generate(upstream, port, prefix, networks, public_reports=False, registration_networks=None):
    address = ipaddress.ip_address(upstream)
    if not address.is_private or address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError('Use the reachable private Home Assistant host address')
    if not 1 <= port <= 65535:
        raise ValueError('Use a valid mapped REST port')
    if not re.fullmatch(r'/(?:[A-Za-z0-9_-]+/)+', prefix):
        raise ValueError('Use a path such as /family-vpn/')
    allowed = validated_networks(networks, 'VPN')
    host = f'[{address}]' if address.version == 6 else str(address)
    acl = '\n'.join(f'    allow {network};' for network in allowed)
    result = f'''# Complete location example: do not nest inside NPM's custom-location Advanced box.
# Use only where the NPM socket peer represents the VPN source; preserve bearer headers.
location {prefix} {{
{acl}
    deny all;
    proxy_pass http://{host}:{port}/;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 2k;
    proxy_connect_timeout 5s;
    proxy_read_timeout 15s;
}}
'''
    if public_reports:
        for route in ('status', 'command-results'):
            result += f'''\n# Authenticated device reporting only; all other routes retain the VPN ACL.
location = {prefix}{route} {{
    limit_except POST {{ deny all; }}
    proxy_pass http://{host}:{port}/{route};
    proxy_set_header Authorization $http_authorization;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 2k;
    proxy_connect_timeout 5s;
    proxy_read_timeout 15s;
}}
'''
    if registration_networks is not None:
        registration = validated_networks(registration_networks, 'registration')
        registration_acl = '\n'.join(f'    allow {network};' for network in registration)
        result += f'''
# Registration has its own source boundary; VPN access does not grant enrollment.
location = {prefix}registrations {{
{registration_acl}
    deny all;
    limit_except POST {{ deny all; }}
    proxy_pass http://{host}:{port}/registrations;
    proxy_set_header Authorization $http_authorization;
    proxy_set_header X-FamilyVPN-Command-Protocol $http_x_familyvpn_command_protocol;
    proxy_set_header X-FamilyVPN-Administrator-Protocol $http_x_familyvpn_administrator_protocol;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    client_max_body_size 2k;
    proxy_connect_timeout 5s;
    proxy_read_timeout 15s;
}}
'''
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', required=True, help='Private Home Assistant host IP reachable from NPM')
    parser.add_argument('--port', type=int, default=8500)
    parser.add_argument('--prefix', default='/family-vpn/')
    parser.add_argument('--allow', action='append', required=True, help='VPN source CIDR or NAT gateway address; repeat for multiple sources')
    parser.add_argument('--public-reports', action='store_true', help='Expose only POST status and command acknowledgements with device authentication')
    parser.add_argument('--registration-allow', action='append', help='Registration-only source CIDR; overrides the VPN ACL for enrollment')
    args = parser.parse_args()
    try: print(generate(args.upstream, args.port, args.prefix, args.allow, args.public_reports, args.registration_allow), end='')
    except ValueError as error: parser.error(str(error))

if __name__ == '__main__': main()
