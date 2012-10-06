#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import sys

if sys.version < '2.5':
    print 'Python 2.5+ required. Sorry :-('
    sys.exit(1)

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(
    name = 'couchdb-auditor',
    version = '0.2',

    description = \
        'Audit configuration and security issues for an Apache CouchDB server.',
    long_description = \
        'Python port of Jason Smith https://github.com/iriscouch/audit_couchdb tool.',
    author = 'Alexander Shorin',
    author_email = 'kxepal@gmail.com',
    license = 'BSD',
    url = 'http://code.google.com/p/couchdb-auditor/',

    install_requires = ['couchdb'],
    entry_points = {
        'console_scripts': [
            'couchdb-auditor = couchdb_auditor:main',
        ],
    },

    packages = ['couchdb_auditor'],
)
