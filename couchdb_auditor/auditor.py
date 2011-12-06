# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import couchdb
import re
import socket
import textwrap
from couchdb_auditor.client import Server

_RULES = {
    'server': []
}

_CVES = [
    { 'id': 'CVE-2010-0009',
      'url': 'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-0009',
      'overview': ('Apache CouchDB 0.8.0 through 0.10.1 allows remote attackers'
                   ' to obtain sensitive information by measuring the'
                   ' completion time of operations that verify (1) hashes or'
                   ' (2) passwords.'),
      'applies': lambda *version: (0, 8, 0) <= version <= (0, 10, 1)
    },
    { 'id': 'CVE-2010-2234',
      'url': 'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-2234',
      'overview': ('Cross-site request forgery (CSRF) vulnerability in'
                   ' Apache CouchDB 0.8.0 through 0.11.0 allows remote'
                   ' attackers to hijack the authentication of administrators'
                   ' for direct requests to an installation URL.'),
      'applies': lambda *version: (0, 8, 0) <= version <= (0, 11, 0)
    },
    { 'id': 'CVE-2010-3854',
      'url': 'http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2010-3854',
      'overview': ('Multiple cross-site scripting (XSS) vulnerabilities in the'
                   ' web administration interface (aka Futon) in'
                   ' Apache CouchDB 0.8.0 through 1.0.1 allow remote attackers'
                   ' to inject arbitrary web script or HTML via unspecified'
                   ' vectors.'),
      'applies': lambda *version: (0, 8, 0) <= version <= (1, 0, 1)
    }
]

def server_rule(func):
    _RULES['server'].append(func)
    return func

def get_rules(name):
    return _RULES[name]

def audit_server(server, log):
    if server.__class__ is couchdb.Server:
        credentials =server.resource.credentials
        server = Server(server.resource.url)
        server.resource.credentials = credentials
    for rule in get_rules('server'):
        try:
            rule(server, log)
        except socket.error, err:
            log.error('%s: %s', err.__class__.__name__, err)
        except couchdb.HTTPError:
            log.error('%s: %s', err.__class__.__name__, err.args[0][1])

@server_rule
def check_version(server, log):
    version = server.version()

    v_match = re.match('^(?P<major>\d+)\.' \
                       '(?P<minor>\d+)\.'  \
                       '(?P<revision>\d+)' \
                       '(?:(?P<stage>[a-z])-' \
                       '(?P<vcs_rev>.*))?$',
                       version)
    if v_match is None:
        log.warning('You have a weird CouchDB version: %s', version)
    else:
        v_struct = v_match.groupdict()
        if v_struct['vcs_rev']:
            log.warn('You have using non release version: %s', version)
        else:
            log.info('CouchDB version: %s', version)

@server_rule
def check_CVE_issues(server, log):
    version = server.version()

    v_match = re.match('^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<revision>\d+).*$',
                       version)
    if v_match is None:
        log.warn('Unable to extract version info from: %s', version)
        return

    version = map(int, v_match.groups())
    affected = False
    for bill in _CVES:
        if bill['applies'](*version):
            overview = '\n'.join(textwrap.wrap(bill['overview'], 80))
            log.error('CVE Vulnerability: %s\n%s\nSee %s',
                      bill['id'], overview, bill['url'])
            affected = True

    if not affected:
        log.info('Not affected by all known issues')

@server_rule
def check_audit_user(server, log):
    session = server.session()

    userctx = session['userCtx']
    roles = '; site-wide roles: %s' % ', '.join(userctx['roles'])
    if userctx['name'] is None:
        if '_admin' in userctx['roles']:
            log.warn('Auditing as: admin party %s', roles)
        else:
            log.warn('Auditing as: anonymous user %s', roles)
    else:
        if '_admin' in userctx['roles']:
            log.info('Auditing as: authenticated admin user %s', roles)
        else:
            log.warn('Auditing as: authenticated regular user %s', roles)
