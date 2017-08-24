#!/usr/bin/env python2
# coding=utf-8

import argparse
import os
import sys
from collections import Counter

parent_dir = os.path.abspath(os.path.dirname(__file__))
vendor_dir = os.path.join(parent_dir, 'vendor')
sys.path.append(vendor_dir)

try:
    from config import INWX_USER, INWX_PASS, INWX_OTP_SECRET
except ImportError:
    print("Make sure to create a configuration file first (check README.md).")
    exit(1)

from vendor.tldextract import TLDExtract
from vendor.inwx import domrobot, getOTP
import vendor.requests as requests
from vendor.requests.exceptions import ConnectionError
from vendor.ipaddress import IPv4Address, IPv6Address, AddressValueError


class Domain(object):
    def __init__(self, fqdn):
        no_cache_extract = TLDExtract(suffix_list_urls=None)
        result = no_cache_extract(fqdn)

        self.fqdn = result.fqdn
        self.domain = result.registered_domain
        self.subdomain = result.subdomain

    def __repr__(self):
        return 'Domain("{fqdn}")'.format(fqdn=self.fqdn)


class IPProvider(object):
    def __init__(self):
        self.V4_POOL = [
            "https://ip4.nnev.de/",
            "http://v4.ident.me/",
            "https://ipv4.icanhazip.com",
            "https://v4.ifconfig.co/ip",
            "https://ipv4.wtfismyip.com/text",
        ]
        self.V6_POOL = [
            "https://ip6.nnev.de/",
            "http://v6.ident.me/",
            "https://ipv6.icanhazip.com",
            "https://v6.ifconfig.co/ip",
            "https://ipv6.wtfismyip.com/text",
        ]

    def _get_ip(self, pool, validator):
        ips = []
        for page in pool:
            reply = requests.get(page, timeout=5, headers={'Accept': 'application/json'})
            maybe_ip = reply.content.strip()

            # Validate
            try:
                ipa = validator(maybe_ip)
                if not ipa.is_private:
                    ips.append(maybe_ip)
            except AddressValueError:
                pass

        return Counter(ips).most_common()[0][0]

    def get_v4(self):
        return self._get_ip(self.V4_POOL, IPv4Address)

    def get_v6(self):
        return self._get_ip(self.V6_POOL, IPv6Address)


class InwxDDNSException(Exception):
    pass


class InwxClient(object):
    def __init__(self):
        self.url = "https://api.domrobot.com/xmlrpc/"
        self.inwx = domrobot(self.url)

    def login(self, user, password, tfa):
        res = self.inwx.account.login({'user': user, 'pass': password})

        # Perform OTP login if enabled
        if 'tfa' in res['resData'] and res['resData']['tfa'] == 'GOOGLE-AUTH':
            self.inwx.account.unlock({'tan': getOTP(tfa)})

    def get_record_id(self, domain, subdomain, record_type):
        res = self.inwx.nameserver.info({
            'domain': domain,
            'type': record_type,
            'name': subdomain
        })

        resData = res['resData']
        if 'count' in resData:
            if resData['count'] == 1:
                return resData['record'][0]['id']
            else:
                raise InwxDDNSException('More than one {} record for {}.'.format(record_type, domain.fqdn))

        return None

    def _update_ip(self, domain, ip, ip_type):
        record_id = self.get_record_id(domain.domain, domain.subdomain, ip_type)

        if record_id is None:
            self.inwx.nameserver.createRecord({
                'domain': domain.domain,
                'type': ip_type,
                'name': domain.subdomain,
                'content': ip,
                'ttl': 300,
            })
        else:
            self.inwx.nameserver.updateRecord({
                'id': record_id,
                'type': ip_type,
                'name': domain.subdomain,
                'content': ip,
                'ttl': 300
            })

    def update_ipv4(self, domain, ipv4):
        self._update_ip(domain, ipv4, 'A')

    def update_ipv6(self, domain, ipv6):
        self._update_ip(domain, ipv6, 'AAAA')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Updates the IP adresses (v4, v6) on inwx.de')
    parser.add_argument('--v4', '-4', action='store_true', help='Update the IPv4 address.')
    parser.add_argument('--v6', '-6', action='store_true', help='Update the IPv6 address.')
    parser.add_argument('--domain', '-d', help='The domain to update the IP addresses in.')
    args = parser.parse_args()

    if not any([args.v4, args.v6]):
        parser.error('Must specify either --v4 / -4 or --v6 / -6')
        exit(1)

    ipp = IPProvider()

    domain = Domain(args.domain)
    inwx_client = InwxClient()
    inwx_client.login(INWX_USER, INWX_PASS, INWX_OTP_SECRET)

    if args.v4:
        try:
            inwx_client.update_ipv4(domain, ipp.get_v4())
        except ConnectionError:
            # Client may not have an IPv4 address.
            pass

    if args.v6:
        try:
            inwx_client.update_ipv6(domain, ipp.get_v6())
        except ConnectionError:
            # Client may not have an IPv4 address.
            pass
