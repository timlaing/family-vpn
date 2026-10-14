import pytest
from Tools.generate_npm_location import generate

class TestProxyConfiguration:
    def test_explicit_sources_prefix_and_bearer_preservation(self):
        result=generate('192.168.1.20',8500,'/family-vpn/',['10.20.30.0/24','10.20.40.1'])
        assert ('allow 10.20.30.0/24;') in (result)
        assert ('allow 10.20.40.1/32;') in (result)
        assert ('deny all;') in (result)
        assert ('proxy_pass http://192.168.1.20:8500/;') in (result)
        assert ('proxy_set_header Authorization $http_authorization;') in (result)
    def test_ipv6_upstream_and_network(self):
        result=generate('fd00::20',8500,'/vpn/control/',['fd01::/64'])
        assert ('proxy_pass http://[fd00::20]:8500/;') in (result)
        assert ('allow fd01::/64;') in (result)
    def test_rejects_open_access_and_configuration_injection(self):
        for networks in ([],['0.0.0.0/0'],['::/0'],['invalid'],['10.0.0.0/24; allow all']):
            with pytest.raises(ValueError): generate('192.168.1.20',8500,'/family-vpn/',networks)
        for prefix in ('/vpn','/vpn/;','/vpn/ { allow all; }'):
            with pytest.raises(ValueError): generate('192.168.1.20',8500,prefix,['10.20.30.0/24'])
        for host in ('example.com','127.0.0.1','0.0.0.0','8.8.8.8','192.168.1.20;'):
            with pytest.raises(ValueError): generate(host,8500,'/family-vpn/',['10.20.30.0/24'])
        for port in (0,65536):
            with pytest.raises(ValueError): generate('192.168.1.20',port,'/family-vpn/',['10.20.30.0/24'])

    def test_public_reports_are_exact_post_only_exceptions(self):
        result=generate('192.168.1.20',8500,'/family-vpn/',['10.20.30.0/24','10.20.40.0/24'],True)
        assert (result.count('location = ')) == (4)
        assert (result.count('limit_except POST { deny all; }')) == (4)
        for route in ('status','command-results','relay-results'):
            assert ('location = /family-vpn/' + route + ' {') in (result)
            assert ('proxy_pass http://192.168.1.20:8500/' + route + ';') in (result)
        assert ('allow 10.20.30.0/24;') in (result)
        assert ('location = /family-vpn/commands') not in (result)
        assert ('location = ') not in (generate('192.168.1.20', 8500, '/family-vpn/', ['10.20.30.0/24']))

    def test_registration_has_separate_lan_boundary(self):
        result=generate('192.168.1.20',8500,'/family-vpn/',['10.20.30.0/24','10.20.40.0/24'],True,['192.168.10.0/24'])
        registration=result.split('location = /family-vpn/registrations {')[1]
        assert ('allow 192.168.10.0/24;') in (registration)
        assert ('allow 10.20.30.') not in (registration)
        assert ('allow 10.20.40.') not in (registration)
        assert ('deny all;') in (registration)
        assert ('limit_except POST { deny all; }') in (registration)
        assert ('proxy_pass http://192.168.1.20:8500/registrations;') in (registration)
        for networks in ([],['0.0.0.0/0'],['::/0'],['bad; allow all']):
            with pytest.raises(ValueError):
                generate('192.168.1.20',8500,'/family-vpn/',['10.20.30.0/24'],True,networks)


def test_hosted_relay_routes_are_explicit_and_worker_header_is_preserved():
    result = generate('192.168.1.20',8500,'/family-vpn/',['10.20.30.0/24'],host_relay=True)
    for route in ('endpoints','rotate','push','ping'):
        assert f'location = /family-vpn/{route}' in result
    assert result.count('proxy_set_header X-Relay-Proxy-Token $http_x_relay_proxy_token;') == 4
    assert 'client_max_body_size 8k;' in result
