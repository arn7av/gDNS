#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import signal

__version__ = '0.0.1'

TORNADO_AVAILABLE = True

# By default, Twisted uses epoll on Linux, poll on other non-OS X POSIX
# platforms and select everywhere else. This means that Twisted will
# use select on Mac OS X instead of kqueue. Tornado uses epoll on Linux,
# kqueue on Mac OS X and select on everywhere else. I think Tornado's choice
# is better than Twisted. So we try to use Tornado IOLoop first, and use Twisted
# default reactor as fallback.
try:
    import tornado.ioloop
    import tornado.platform.twisted

    tornado.platform.twisted.install()
except ImportError:
    TORNADO_AVAILABLE = False

from twisted.internet import reactor, defer, error
from twisted.names import dns, server, cache, common
from twisted.python import log, failure
from rr import RECORD_TYPES, UnknownRecord

import requests
from requests_toolbelt.adapters.host_header_ssl import HostHeaderSSLAdapter

version_parts = sys.version_info
if not (version_parts[0] == 3 and version_parts[1] >= 4):
    print("python 3.4 required")
    sys.exit(1)

DEFAULT_LOCAL_ADDRESS = '127.0.0.1'
# DEFAULT_LOCAL_PORT = 53
DEFAULT_LOCAL_PORT = 1053


def get_dns_json(query_name, query_type):
    s = requests.Session()
    s.mount('https://', HostHeaderSSLAdapter())
    j = s.get('https://216.58.220.46/resolve', params={'name': query_name, 'type': query_type}, headers={'host': 'dns.google.com'}).json()
    log.msg(j)
    return j


def json_name_to_bytes(s):
    return s.encode('ascii').decode('idna').encode('utf-8')


class JSONMessage(dns.Message):
    _recordTypes = RECORD_TYPES

    def lookupRecordType(self, type):
        return self._recordTypes.get(type, UnknownRecord)

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
            self.queries.append(dns.Query(json_name_to_bytes(q['name']), q['type']))

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
                name=json_name_to_bytes(record['name']),
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
    query_name = query.name.name
    query_type = query.type
    if isinstance(query_name, bytes):
        query_name_unicode = query_name.decode('utf-8')
        query_name_idna = query_name_unicode.encode('idna')
    else:
        query_name_idna = query_name
    j = get_dns_json(query_name_idna, query_type)
    m = JSONMessage()
    m.fromJSON(j)
    return m


class GoogleResolver(common.ResolverBase):

    def __init__(self, query_timeout=None, verbose=0):
        common.ResolverBase.__init__(self)
        self.timeout = query_timeout
        self.verbose = verbose
        self._waiting = {}

    def queryGoogle(self, queries, timeout=None):
        d = defer.Deferred()
        d.addCallback(getParsedMessage, timeout=timeout)
        query = queries[0]
        d.callback(query)
        return d

    def _lookup(self, name, cls, type, timeout):
        key = (name, type, cls)
        waiting = self._waiting.get(key)
        if waiting is None:
            self._waiting[key] = []
            # d = self.queryUDP([dns.Query(name, type, cls)], timeout)
            d = self.queryGoogle([dns.Query(name, type, cls)], timeout)

            def cbResult(result):
                for d in self._waiting.pop(key):
                    d.callback(result)
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
        if message.rCode != dns.OK:
            return failure.Failure(self.exceptionForCode(message.rCode)(message))
        return (message.answers, message.authority, message.additional)


def try_exit_tornado_ioloop():
    print('Exiting')
    tornado.ioloop.IOLoop.instance().stop()


def main():
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

    args = parser.parse_args()
    if not args.quiet:
        log.startLogging(sys.stdout)

    addr = args.bind_addr
    port = args.bind_port
    log.msg("Listening on " + addr + ':' + str(port))

    factory = server.DNSServerFactory(
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
