# -*- coding: utf-8 -*-

from twisted.names import dns


class SimpleRecord(dns.SimpleRecord):
    def decodeJSON(self, data):
        self.__init__(name=data, ttl=self.ttl)


class Record_A(dns.Record_A):
    def decodeJSON(self, data):
        self.__init__(address=data, ttl=self.ttl)


class Record_A6(dns.Record_A6):
    pass


class Record_AAAA(dns.Record_AAAA):
    def decodeJSON(self, data):
        self.__init__(address=data, ttl=self.ttl)


class Record_AFSDB(dns.Record_AFSDB):
    pass


class Record_CNAME(dns.Record_CNAME, SimpleRecord):
    pass


class Record_DNAME(dns.Record_DNAME, SimpleRecord):
    pass


class Record_HINFO(dns.Record_HINFO):
    def decodeJSON(self, data):
        cpu, os = data.split(maxsplit=1)
        self.__init__(cpu.encode('utf-8'), os.encode('utf-8'), ttl=self.ttl)


class Record_MB(dns.Record_MB, SimpleRecord):
    pass


class Record_MD(dns.Record_MD, SimpleRecord):
    pass


class Record_MF(dns.Record_MF, SimpleRecord):
    pass


class Record_MG(dns.Record_MG, SimpleRecord):
    pass


class Record_MINFO(dns.Record_MINFO):
    pass


class Record_MR(dns.Record_MR, SimpleRecord):
    pass


class Record_MX(dns.Record_MX):
    def decodeJSON(self, data):
        preference, name = data.split()
        self.__init__(int(preference), name, ttl=self.ttl)


class Record_NAPTR(dns.Record_NAPTR):
    pass


class Record_NS(dns.Record_NS, SimpleRecord):
    pass


class Record_NULL(dns.Record_NULL):
    def decodeJSON(self, data):
        self.__init__(payload=data, ttl=self.ttl)


class Record_PTR(dns.Record_PTR, SimpleRecord):
    pass


class Record_RP(dns.Record_RP):
    pass


class Record_SOA(dns.Record_SOA):
    def decodeJSON(self, data):
        mname, rname, serial, refresh, retry, expire, minimum = data.split()
        self.__init__(mname, rname, int(serial), int(refresh), int(retry), int(expire), int(minimum), ttl=self.ttl)


class Record_SRV(dns.Record_SRV):
    def decodeJSON(self, data):
        priority, weight, port, target = data.split()
        self.__init__(int(priority), int(weight), int(port), target, ttl=self.ttl)


class Record_TXT(dns.Record_TXT):
    def decodeJSON(self, data):
        l = data.split('"')[1::2]
        l_bytes = [i.encode('utf-8') for i in l]
        self.__init__(*l_bytes, ttl=self.ttl)


class Record_WKS(dns.Record_WKS):
    pass


class UnknownRecord(dns.UnknownRecord):
    def decodeJSON(self, data):
        self.__init__(data=data.encode('utf-8'), ttl=self.ttl)


class Record_SPF(dns.Record_SPF, Record_TXT):
    pass


RECORD_CLASSES = {
    'Record_A': Record_A,
    'Record_A6': Record_A6,
    'Record_AAAA': Record_AAAA,
    'Record_AFSDB': Record_AFSDB,
    'Record_CNAME': Record_CNAME,
    'Record_DNAME': Record_DNAME,
    'Record_HINFO': Record_HINFO,
    'Record_MB': Record_MB,
    'Record_MD': Record_MD,
    'Record_MF': Record_MF,
    'Record_MG': Record_MG,
    'Record_MINFO': Record_MINFO,
    'Record_MR': Record_MR,
    'Record_MX': Record_MX,
    'Record_NAPTR': Record_NAPTR,
    'Record_NS': Record_NS,
    'Record_NULL': Record_NULL,
    'Record_PTR': Record_PTR,
    'Record_RP': Record_RP,
    'Record_SOA': Record_SOA,
    'Record_SPF': Record_SPF,
    'Record_SRV': Record_SRV,
    'Record_TXT': Record_TXT,
    'Record_WKS': Record_WKS,
}

RECORD_TYPES = {}

for record_name, record_class in RECORD_CLASSES.items():
    RECORD_TYPES[record_class.TYPE] = record_class
