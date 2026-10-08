import unittest
from Tools.generate_npm_location import generate

class ProxyConfigurationTests(unittest.TestCase):
    def test_explicit_sources_prefix_and_bearer_preservation(self):
        result=generate('192.168.1.20',8081,'/family-vpn/',['10.20.30.0/24','10.20.40.1'])
        self.assertIn('allow 10.20.30.0/24;',result)
        self.assertIn('allow 10.20.40.1/32;',result)
        self.assertIn('deny all;',result)
        self.assertIn('proxy_pass http://192.168.1.20:8081/;',result)
        self.assertIn('proxy_set_header Authorization $http_authorization;',result)
    def test_ipv6_upstream_and_network(self):
        result=generate('fd00::20',8081,'/vpn/control/',['fd01::/64'])
        self.assertIn('proxy_pass http://[fd00::20]:8081/;',result)
        self.assertIn('allow fd01::/64;',result)
    def test_rejects_open_access_and_configuration_injection(self):
        for networks in ([],['0.0.0.0/0'],['::/0'],['invalid'],['10.0.0.0/24; allow all']):
            with self.assertRaises(ValueError): generate('192.168.1.20',8081,'/family-vpn/',networks)
        for prefix in ('/','/vpn','/vpn/;','/vpn/ { allow all; }'):
            with self.assertRaises(ValueError): generate('192.168.1.20',8081,prefix,['10.20.30.0/24'])
        for host in ('example.com','127.0.0.1','0.0.0.0','8.8.8.8','192.168.1.20;'):
            with self.assertRaises(ValueError): generate(host,8081,'/family-vpn/',['10.20.30.0/24'])
        for port in (0,65536):
            with self.assertRaises(ValueError): generate('192.168.1.20',port,'/family-vpn/',['10.20.30.0/24'])

    def test_public_reports_are_exact_post_only_exceptions(self):
        result=generate('192.168.15.133',8081,'/family-vpn/',['192.168.201.0/24','192.168.202.0/24'],True)
        self.assertEqual(result.count('location = '),2)
        self.assertEqual(result.count('limit_except POST { deny all; }'),2)
        for route in ('status','command-results'):
            self.assertIn('location = /family-vpn/'+route+' {',result)
            self.assertIn('proxy_pass http://192.168.15.133:8081/'+route+';',result)
        self.assertIn('allow 192.168.201.0/24;',result)
        self.assertNotIn('location = /family-vpn/commands',result)
        self.assertNotIn('location = ',generate('192.168.15.133',8081,'/family-vpn/',['192.168.201.0/24']))

    def test_registration_has_separate_lan_boundary(self):
        result=generate('192.168.15.133',8081,'/family-vpn/',['192.168.201.0/24','192.168.202.0/24'],True,['192.168.150.0/24'])
        registration=result.split('location = /family-vpn/registrations {')[1]
        self.assertIn('allow 192.168.150.0/24;',registration)
        self.assertNotIn('allow 192.168.201.',registration)
        self.assertNotIn('allow 192.168.202.',registration)
        self.assertIn('deny all;',registration)
        self.assertIn('limit_except POST { deny all; }',registration)
        self.assertIn('proxy_pass http://192.168.15.133:8081/registrations;',registration)
        for networks in ([],['0.0.0.0/0'],['::/0'],['bad; allow all']):
            with self.assertRaises(ValueError):
                generate('192.168.15.133',8081,'/family-vpn/',['192.168.201.0/24'],True,networks)
