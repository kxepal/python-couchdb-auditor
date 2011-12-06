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

def get_cached_value(cache, key, func):
    if key not in cache:
        cache[key] = func()
    return cache[key]

def audit_server(server, log, no_cache=False):
    if server.__class__ is couchdb.Server:
        credentials =server.resource.credentials
        server = Server(server.resource.url)
        server.resource.credentials = credentials
    cache = {}
    for rule in get_rules('server'):
        try:
            rule(server, log, no_cache and {} or cache)
        except socket.error, err:
            log.error('%s: %s', err.__class__.__name__, err)
        except couchdb.HTTPError, err:
            log.error('%s: %s', err.__class__.__name__, err.args[0][1])

@server_rule
def check_version(server, log, cache):
    version = get_cached_value(cache, 'version', server.version)

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
def check_CVE_issues(server, log, cache):
    version = get_cached_value(cache, 'version', server.version)

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
def check_audit_user(server, log, cache):
    session = get_cached_value(cache, 'session', server.session)

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

@server_rule
def check_config_access(server, log, cache):
    try:
        server.config()
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    credentials = server.resource.credentials
    try:
        server.resource.credentials = None
        server.config()
    except couchdb.Unauthorized:
        log.info('Configuration is closed for anonymous users')
    else:
        log.error('Configuration is open for anyone')
    finally:
        server.resource.credentials = credentials

@server_rule
def check_admins(server, log, cache):
    try:
        config = get_cached_value(cache, 'config', server.config)
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    admins = config.get('admins')
    if not admins:
        log.error('This couch is in Admin Party.'
                  ' Log in to Futon (/_utils) and click "Fix this": '
                  '%s' % server.resource('_utils').url)
    else:
        count = len(admins)
        if count == 1:
            log.info('There is only one admin on couch: %s', admins[0]),
        else:
            log.warn('In production, admins should be used rarely,'
                      ' but yet you have many (%d):'
                      ' %s', count, ', '.join(admins))

@server_rule
def check_geocouch(server, log, cache):
    try:
        config = get_cached_value(cache, 'config', server.config)
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    httpd_design_handlers = config['httpd_design_handlers']
    possible_geocouch_handlers = [
        '_spatial', '_spatial/_list', '_spatial/_info', '_spatial/_compact'
    ]
    for key in possible_geocouch_handlers:
        if not key in httpd_design_handlers:
            break
    else:
        log.info('Looks like GeoCouch is plugged in')

@server_rule
def check_browserid(server, log, cache):
    try:
        config = get_cached_value(cache, 'config', server.config)
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    if 'browserid' in config and '_browserid' in config['httpd_global_handlers']:
        log.info('Looks like BrowserID is plugged in')
