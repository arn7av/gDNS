# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, unicode_literals

from twisted.names.dns import Name
from twisted.python.compat import unicode


def patched_name_init(self, name=b''):
    """
    @type name: L{unicode} L{bytes}
    """
    if isinstance(name, unicode):
        try:
            name = name.encode('idna')
        except UnicodeError:
            if name[-1:] == '.':
                name = name[:-1]
            name = name.replace('\\.', '.')
            name = name.encode('utf-8')
    if not isinstance(name, bytes):
        raise TypeError("%r is not a byte string" % (name,))
    self.name = name


def apply_patches():
    Name.__init__ = patched_name_init
