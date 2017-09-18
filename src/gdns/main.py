#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import argparse
import signal
from copy import copy

__version__ = '0.1.4'

TORNADO_AVAILABLE = True

# By default, Twisted uses epoll on Linux, poll on other non-OS X POSIX
# platforms and select everywhere else. This means that Twisted will
# use select on Mac OS X instead of kqueue. Tornado uses epoll on Linux,
# kqueue on Mac OS X and select on everywhere else. I think Tornado's choice
# is better than Twisted. So we try to use Tornado IOLoop first, and use Twisted
# default reactor as fallback.

try:
    # noinspection PyUnresolvedReferences
    import tornado.ioloop
    # noinspection PyUnresolvedReferences
    import tornado.platform.twisted
except ImportError:
    TORNADO_AVAILABLE = False
else:
    # avoid ReactorAlreadyInstalledError when using PyInstaller
    if 'twisted.internet.reactor' in sys.modules:
        del sys.modules['twisted.internet.reactor']
    tornado.platform.twisted.install()

from twisted.internet import reactor, defer, error, task
from twisted.names import dns, server, common
from twisted.python import log, failure
from gdns.rr import RECORD_TYPES
from gdns.patches import apply_patches

import requests
from requests_toolbelt.adapters.host_header_ssl import HostHeaderSSLAdapter

apply_patches()


DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
# DEFAULT_LOCAL_PORT = 53
DEFAULT_LOCAL_PORT = 1053

# dns.google.com
# https://dns.google.com/resolve?name=dns.google.com&edns_client_subnet=0.0.0.0/0
google_dns_host = 'dns.google.com'
google_dns_ip_pool = [
    '172.217.24.110',
    '172.217.26.78',
    '172.217.27.14',
    '172.217.27.46',
    '172.217.27.110',
    '173.194.202.100',
    '74.125.24.100',
    '74.125.68.100',
    '74.125.130.100',
    '74.125.200.100',
    '74.125.204.100',
    '216.58.203.238',
    '216.58.220.46',
    '216.58.221.78',
]
google_dns_ip = google_dns_ip_pool[0]
edns_client_subnet = None
# edns_client_subnet = '0.0.0.0/0'
validate_dnssec = False


def get_dns_json(query_name, query_type, edns_client_subnet=edns_client_subnet, validate_dnssec=validate_dnssec):
    s = requests.Session()
    s.mount('https://', HostHeaderSSLAdapter())
    u = 'https://{}/resolve'.format(google_dns_ip)
    params = {'name': query_name, 'type': query_type, 'cd': validate_dnssec}
    if edns_client_subnet:
        params['edns_client_subnet'] = edns_client_subnet
    try:
        j = s.get(u, params=params, headers={'host': google_dns_host}).json()
    except requests.exceptions.RequestException as e:
        # log.debug(e.__class__.__name__)
        pass
    else:
        log.msg(j)
        return j


def resolve_google_dns_ip():
    j = get_dns_json(google_dns_host, dns.A)
    if not j:
        return
    a = j.get('Answer', [])
    if len(a) > 0:
        return a[0].get('data', None)


def json_name_to_dns_name(s):
    # if names are going to be valid regardless
    return s.encode('ascii')
    # if we want our patched Name to handle edge cases
    # return s.encode('ascii').decode('idna')


def bytes_to_json_name(b):
    return b.decode('utf-8').encode('idna').decode('ascii')


class JSONMessage(dns.Message):
    _recordTypes = RECORD_TYPES

    def fromJSON(self, j):
        self.maxSize = 0
        self.answer = 1
        self.opCode = dns.OP_QUERY
        self.auth = 0
        self.trunc = int(j['TC'])
        self.recDes = int(j['RD'])
        self.recAv = int(j['RA'])
        self.authenticData = int(j['AD'])
        self.checkingDisabled = int(j['CD'])
        self.rCode = j['Status']

        self.queries = []
        for q in j['Question']:
            self.queries.append(dns.Query(json_name_to_dns_name(q['name']), q['type']))

        items = (
            (self.answers, j.get('Answer', [])),
            (self.authority, j.get('Authority', [])),
            (self.additional, j.get('Additional', []))
        )

        for (item, records) in items:
            self.parseRecordsJSON(item, records)

    def parseRecordsJSON(self, item, records):
        for record in records:
            header = dns.RRHeader(
                name=json_name_to_dns_name(record['name']),
                type=record['type'],
                ttl=record.get('TTL', 0),
                auth=self.auth
            )
            t = self.lookupRecordType(header.type)
            if not t:
                continue
            header.payload = t(ttl=header.ttl)
            header.payload.decodeJSON(record.get('data', ''))
            item.append(header)


def getParsedMessage(query, timeout=None):
    query_name = query.name.name  # unicode_sample = b'\xe0\xa4\xad\xe0\xa4\xbe\xe0\xa4\xb0\xe0\xa4\xa4.icom.museum'
    query_type = query.type
    if isinstance(query_name, bytes):
        query_name_idna = bytes_to_json_name(query_name)
    else:
        query_name_idna = query_name
    j = get_dns_json(query_name_idna, query_type)
    d = defer.Deferred()
    if j:
        m = JSONMessage()
        m.fromJSON(j)
        # return m
        d.callback(m)
    else:
        f = failure.Failure(ConnectionError('unable to fetch dns'))
        d.errback(f)
    return d


class GoogleResolver(common.ResolverBase):

    def __init__(self, query_timeout=None, verbose=0, reactor=None):
        common.ResolverBase.__init__(self)

        if reactor is None:
            from twisted.internet import reactor
        self._reactor = reactor

        self.timeout = query_timeout
        self.verbose = verbose
        self._waiting = {}

    def queryGoogle(self, queries, timeout=None):
        query = queries[0]
        d = task.deferLater(self._reactor, 0, getParsedMessage, query, timeout=timeout)
        return d

    def _lookup(self, name, cls, type, timeout):
        key = (name, type, cls)
        waiting = self._waiting.get(key)
        if waiting is None:
            self._waiting[key] = []
            # d = self.queryUDP([dns.Query(name, type, cls)], timeout)
            d = self.queryGoogle([dns.Query(name, type, cls)], timeout)

            def cbResult(result):
                for d_waiting in self._waiting.pop(key):
                    d_waiting.callback(result)
                return result
            d.addCallback(self.filterAnswers)
            d.addBoth(cbResult)
        else:
            d = defer.Deferred()
            waiting.append(d)
        return d

    def filterAnswers(self, message):
        # if message.trunc:
        #     pass
        # if message.rCode != dns.OK:
        #     return failure.Failure(self.exceptionForCode(message.rCode)(message))
        # return (message.answers, message.authority, message.additional)
        return message


class ExtensibleDNSServerFactory(server.DNSServerFactory):

    def _generateFinalMessage(self, response_message, request_message):
        final_message = copy(response_message)
        final_message.id = request_message.id
        final_message.queries = request_message.queries[:]
        final_message.timeReceived = getattr(request_message, 'timeReceived', None)
        return final_message

    def gotResolverResponse(self, response_message, protocol, request_message, address):
        response = self._generateFinalMessage(response_message, request_message)
        ans, auth, add = response_message.answers, response_message.authority, response_message.additional
        # response = self._responseFromMessage(
        #     message=message, rCode=dns.OK,
        #     answers=ans, authority=auth, additional=add)
        self.sendReply(protocol, response, address)

        l = len(ans) + len(auth) + len(add)
        self._verboseLog("Lookup found %d record%s" % (l, l != 1 and "s" or ""))

        if self.cache and l:
            self.cache.cacheResult(
                request_message.queries[0], (ans, auth, add)
            )


def try_exit_tornado_ioloop():
    print('Exiting')
    tornado.ioloop.IOLoop.instance().stop()


def main():
    global google_dns_ip

    parser = argparse.ArgumentParser(
        description="Google DNS-over-HTTPS")
    parser.add_argument('-b', '--bind-addr', type=str,
                        help='local address to listen',
                        default=DEFAULT_LOCAL_ADDRESS,
                        )
    parser.add_argument('-p', '--bind-port', type=int,
                        help="local port to listen",
                        default=DEFAULT_LOCAL_PORT,
                        )
    parser.add_argument('--query-timeout', type=int,
                        help="time before close port used for querying",
                        default=10)
    parser.add_argument('-t', '--tcp-server',
                        help="enables TCP serving",
                        action="store_true")
    parser.add_argument('-v', '--verbosity', type=int,
                        choices=[0, 1, 2],
                        help="output verbosity",
                        default=0)
    parser.add_argument('-q', '--quiet',
                        help="disable output",
                        action='store_true')
    parser.add_argument('-V', '--version',
                        action='version',
                        version="gdns " + str(__version__))
    parser.add_argument('-G', '--google-dns-ip', type=str,
                        help='dns.google.com ip',
                        default=google_dns_ip,
                        )

    args = parser.parse_args()
    if not args.quiet:
        log.startLogging(sys.stdout)

    addr = args.bind_addr
    port = args.bind_port
    log.msg('Listening on ' + addr + ':' + str(port))

    google_dns_ip = args.google_dns_ip
    fresh_google_dns_ip = resolve_google_dns_ip()
    if fresh_google_dns_ip:
        google_dns_ip = fresh_google_dns_ip
    else:
        log.err(ConnectionError('unable to refresh dns.google.com ip'))
    log.msg('dns.google.com ip ' + google_dns_ip)

    factory = ExtensibleDNSServerFactory(
        clients=[GoogleResolver(query_timeout=args.query_timeout, verbose=args.verbosity)],
        verbose=args.verbosity
    )

    protocol = dns.DNSDatagramProtocol(controller=factory)
    if args.verbosity < 2:
        dns.DNSDatagramProtocol.noisy = False
        server.DNSServerFactory.noisy = False
    try:
        reactor.listenUDP(port, protocol, addr)
        if args.tcp_server:
            reactor.listenTCP(
                port, factory, interface=addr)
        if TORNADO_AVAILABLE:
            if args.verbosity > 1:
                log.msg("Using Tornado ioloop")
            signal.signal(signal.SIGINT, lambda sig, frame: tornado.ioloop.IOLoop.instance().add_callback_from_signal(
                try_exit_tornado_ioloop))
            tornado.ioloop.IOLoop.instance().start()
        else:
            if args.verbosity > 1:
                log.msg("Using Twisted reactor")
            reactor.run()
    except error.CannotListenError:
        log.msg(
            "Can not listen on " + addr + ':' + str(port))
        log.msg('Check if BIND_PORT is already in use')
        log.msg('Try to run this with sudo')


if __name__ == "__main__":
    raise SystemExit(main())
