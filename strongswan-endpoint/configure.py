#!/usr/bin/env python3
"""Create a private IKEv2 endpoint configuration; no passwords on command lines."""
import argparse
import getpass
import ipaddress
import os
from pathlib import Path
import re
import subprocess


def validate(server, pool, dns, username, lan, allowed):
    if not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?', server):
        raise ValueError('Use a gateway DNS hostname, without URL or port')
    if any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in server.split('.')):
        raise ValueError('Use a valid gateway DNS hostname')
    try: ipaddress.ip_address(server)
    except ValueError: pass
    else: raise ValueError('Use a DNS hostname, not an IP address')
    network = ipaddress.IPv4Network(pool)
    if not network.is_private or network.prefixlen < 16 or network.prefixlen > 29:
        raise ValueError('Use a private IPv4 VPN pool between /16 and /29')
    ipaddress.IPv4Address(dns)
    if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', username): raise ValueError('Use a simple device username')
    networks = [ipaddress.IPv4Network(value) for value in lan.split()]
    permitted = [ipaddress.IPv4Network(value) for value in allowed.split()]
    if not networks or not permitted or any(not n.is_private or n.prefixlen == 0 for n in networks+permitted):
        raise ValueError('Supply explicit private LAN and allowed destination CIDRs')
    if any(network.overlaps(n) for n in networks): raise ValueError('VPN pool must not overlap LAN networks')
    if any(not any(n.subnet_of(parent) for parent in networks) for n in permitted):
        raise ValueError('Allowed destinations must be inside the declared LAN networks')
    return network


def create(output, server, pool, dns, username, password, lan, allowed, certificate_days=365):
    network = validate(server,pool,dns,username,lan,allowed)
    if len(password) < 16 or len(password) > 256 or any(ord(c)<33 or ord(c)>126 or c in {chr(34),chr(92)} for c in password):
        raise ValueError('Use a 16-256 character printable password without quotes or backslashes')
    output = Path(output)
    if output.exists() and any(output.iterdir()): raise ValueError('Output is not empty; preserve existing keys and configure additional accounts manually')
    os.umask(0o077)
    for folder in ('swanctl/x509','swanctl/x509ca','swanctl/private','swanctl/conf.d','swanctl/x509ocsp','swanctl/x509aa','swanctl/x509ac','swanctl/x509crl','swanctl/pubkey','swanctl/rsa','swanctl/ecdsa','swanctl/pkcs8','swanctl/pkcs12','ca'):
        (output/folder).mkdir(parents=True,exist_ok=True)
    def openssl(*args):
        subprocess.run(['openssl',*map(str,args)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    ca = output/'ca/ca-key.pem'
    root = output/'swanctl/x509ca/family-vpn-ca.pem'
    key = output/'swanctl/private/vpn-server-key.pem'
    csr = output/'ca/server.csr'
    openssl('req','-x509','-newkey','rsa:3072','-nodes','-sha256','-days','3650','-subj','/CN=Family VPN CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',ca,'-out',root)
    openssl('req','-new','-newkey','rsa:3072','-nodes','-sha256','-subj','/CN='+server,'-keyout',key,'-out',csr)
    extension=output/'ca/server.ext'
    extension.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:'+server+'\n')
    openssl('x509','-req','-in',csr,'-CA',root,'-CAkey',ca,'-CAserial',output/'ca/serial','-CAcreateserial','-days',certificate_days,'-sha256','-extfile',extension,'-out',output/'swanctl/x509/vpn-server.pem')
    config = Path(__file__).with_name('swanctl.conf.template').read_text()
    config = config.replace('VPN_HOSTNAME',server).replace('VPN_POOL_RANGE',str(network.network_address+1)+'-'+str(network.broadcast_address-1)).replace('VPN_DNS',dns)
    (output/'swanctl/swanctl.conf').write_text(config)
    (output/'swanctl/conf.d/family-vpn-secrets.conf').write_text('secrets {\n    eap-device {\n        id = "'+username+'"\n        secret = "'+password+'"\n    }\n}\n')
    (output/'gateway.env').write_text('VPN_POOL_CIDR='+str(network)+'\nVPN_LAN_CIDRS='+lan+'\nVPN_ALLOWED_LAN_CIDRS='+allowed+'\n')
    print('Created endpoint configuration. Upload only swanctl/x509ca/family-vpn-ca.pem to the dashboard. Keep ca/ offline; do not mount it into the gateway.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='runtime')
    parser.add_argument('--server',required=True)
    parser.add_argument('--pool',default='10.20.30.0/24')
    parser.add_argument('--dns',required=True)
    parser.add_argument('--username',required=True)
    parser.add_argument('--lan',required=True,help='Space-separated private LAN CIDRs')
    parser.add_argument('--allow-lan',required=True,help='Space-separated private destinations permitted to VPN devices')
    args=parser.parse_args()
    try:
        password=getpass.getpass('VPN device password (at least 16 characters): ')
        if password != getpass.getpass('Confirm password: '): raise ValueError('Passwords do not match')
        create(args.output,args.server,args.pool,args.dns,args.username,password,args.lan,args.allow_lan)
    except (ValueError,subprocess.CalledProcessError) as exc: parser.error(str(exc))


if __name__=='__main__': main()
