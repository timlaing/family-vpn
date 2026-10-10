#!/usr/bin/env python3
"""Generate a complete Nginx location; never apply changes to a running proxy."""
import argparse


from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from family_vpn.proxy import generate  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', required=True, help='Private Home Assistant host IP reachable from NPM')
    parser.add_argument('--port', type=int, default=8500)
    parser.add_argument('--prefix', default='/family-vpn/')
    parser.add_argument('--allow', action='append', required=True, help='VPN source CIDR or NAT gateway address; repeat for multiple sources')
    parser.add_argument('--public-reports', action='store_true', help='Expose only POST status and command acknowledgements with device authentication')
    parser.add_argument('--registration-allow', action='append', help='Registration-only source CIDR; overrides the VPN ACL for enrollment')
    parser.add_argument('--host-relay', action='store_true', help='Expose hosted relay POST routes, authenticated by the private Worker credential')
    args = parser.parse_args()
    try: print(generate(args.upstream, args.port, args.prefix, args.allow, args.public_reports, args.registration_allow, args.host_relay), end='')
    except ValueError as error: parser.error(str(error))

if __name__ == '__main__': main()
