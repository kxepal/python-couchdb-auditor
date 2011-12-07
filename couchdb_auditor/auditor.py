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

_RULES = {
    'server': [],
    'database': [],
    'ddoc': [],
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

def database_rule(func):
    _RULES['database'].append(func)
    return func

def ddoc_rule(func):
    _RULES['ddoc'].append(func)
    return func

def get_rules(name):
    return _RULES[name]

def get_cached_value(cache, key, func):
    if key not in cache:
        cache[key] = func()
    return cache[key]

def audit_server(server, log, cache=None):
    log.info('%s', server.resource.url)
    for rule in get_rules('server'):
        try:
            if cache is not None:
                rule(server, log, cache)
            else:
                rule(server, log, {})
        except socket.error, err:
            log.error('%s: %s', err.__class__.__name__, err)
        except couchdb.HTTPError, err:
            log.error('%s: %s', err.__class__.__name__, err.args[0][1])

def audit_database(db, log, cache=None):
    try:
        log.info('%s', db.name)
        db.resource.head()
    except socket.error, err:
        log.error('%s: %s', err.__class__.__name__, err)
    except couchdb.HTTPError, err:
        log.error('%s: %s', err.__class__.__name__, err.args[0][1])
    else:
        for rule in get_rules('database'):
            try:
                if cache is not None:
                    rule(db, log, cache)
                else:
                    rule(db, log, {})
            except socket.error, err:
                log.error('%s: %s', err.__class__.__name__, err)
            except couchdb.HTTPError, err:
                log.error('%s: %s', err.__class__.__name__, err.args[0][1])

def audit_ddoc(ddoc, log, cache=None):
    log.info('%s', ddoc['_id'])
    for rule in get_rules('ddoc'):
        if cache is not None:
            rule(ddoc, log, cache)
        else:
            rule(ddoc, log, {})

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

    version = [int(item) for item in v_match.groups()]
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
    get_session = lambda: server.resource('_session').get_json()[2]
    session = get_cached_value(cache, 'session', get_session)

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
            log.info('There is only one admin on couch: %s', admins.keys()[0])
        else:
            log.warn('In production, admins should be used rarely,'
                      ' but yet you have many (%d):'
                      ' %s', count, ', '.join(admins))

@server_rule
def check_auth_handlers(server, log, cache):
    get_session = lambda: server.resource('_session').get_json()[2]
    session = get_cached_value(cache, 'session', get_session)

    default_handlers = ['oauth', 'cookie', 'default']
    server_handlers = session['info']['authentication_handlers']
    no_problems = True

    for handler in default_handlers:
        if handler not in server_handlers:
            no_problems = False
            log.error('Default authentication handler missed: %s', handler)

    for handler in server_handlers:
        if handler not in server_handlers:
            no_problems = False
            log.warn('Non-standard authentication handler: ', handler)

    if no_problems:
        handlers = ', '.join(default_handlers)
        log.info('Authentication handlers are well known: %s' % handlers)

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

@server_rule
def check_facebook_auth(server, log, cache):
    try:
        config = get_cached_value(cache, 'config', server.config)
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    if 'fb' in config and '_fb' in config['httpd_global_handlers']:
        log.info('Looks like Facebook Authentication is plugged in')

@server_rule
def check_query_servers(server, log, cache):
    try:
        config = get_cached_value(cache, 'config', server.config)
    except couchdb.Unauthorized:
        log.error('Unable to audit config.'
                  ' Try to re-run this probe as an admin.')
        return

    query_servers = config['query_servers']
    default_qs = ['javascript', 'coffeescript']
    for item in query_servers:
        if item not in default_qs:
            log.warn('Using non standard query server: %s', item)

@server_rule
def check_auth_db(server, log, cache):
    get_session = lambda: server.resource('_session').get_json()[2]
    session = get_cached_value(cache, 'session', get_session)

    auth_db = session['info']['authentication_db']
    if auth_db != '_users':
        log.warn('Non-standard authentication database: %s', auth_db)

    try:
        server.resource(auth_db).head()
    except couchdb.HTTPError:
        log.warn('Authentication database is not accessible from outside')

@server_rule
def check_db_users(server, log, cache):
    def get_users(db):
        users = {}
        for _id in db:
            if _id.startswith('_design'):
                continue
            users[_id] = db[_id]
        return users
    get_session = lambda: server.resource('_session').get_json()[2]
    session = get_cached_value(cache, 'session', get_session)

    auth_db = session['info']['authentication_db']
    db = couchdb.Database(server.resource(auth_db).url)
    db.resource.credentials = server.resource.credentials
    try:
        db.resource.head()
    except couchdb.HTTPError:
        log.warn('Authentication database is not accessible from outside')
        return

    users = None
    try:
        db.resource.credentials = None
        users = get_users(db)
    except couchdb.Unauthorized:
        log.info('Anonymous users could not observe authentication database')
    finally:
        db.resource.credentials = server.resource.credentials

    if users:
        log.warn('Anonymous users could knew everything about your users!')
    else:
        users = get_users(db)
        if users:
            if '_admin' not in session['userCtx']['roles']:
                log.warn('Registered users could knew about others.')
        elif users is None:
            log.info('_all_docs view is not available for authentication'
                     ' database')

    if users is not None:
        args = 'Found about %d registered users', len(users)
        if len(users):
            log.info(*args)
        else:
            log.warn(*args)
        cache['users'] = users

@database_rule
def check_db_security(db, log, cache):
    _, _, security = db.resource('_security').get_json()

    db_admins = security.get('admins', {})
    db_members = security.get('readers', {})
    has_admins = db_admins.get('names') or db_admins.get('roles')
    has_members = db_members.get('names') or db_members.get('roles')

    session = cache.get('session')
    if not session:
        config = cache.get('config')
        if not config:
            log.warn('Could not determine user permission.'
                     ' Hope there is no admin party')
            userctx = {'name': None, 'roles': []}
        elif config['admins']:
            userctx = {'name': None, 'roles': []}
        else:
            userctx = {'name': None, 'roles': ['_admin']}
    else:
        userctx = session['userCtx']

    admin_party = userctx['name'] is None and '_admin' in userctx['roles']

    if admin_party:
        log.error('Database shares Admin Party state!'
                  ' Anyone could drop it with all %d documents', len(db))
    else:
        if has_admins:
            log.info('Database has it own administrators')
        if not has_members:
            log.warn('Database is public')

    ddocs = []
    for row in db.view('_all_docs', startkey='_design/',  endkey='_design0'):
        ddoc = db[row.id]
        if 'validate_doc_update' in ddoc:
            ddocs.append(row.id)

    if not ddocs:
        log.error('Database is not protected by validation functions!')
    else:
        log.info('Database is protected by next design documents: %s',
                 ', '.join([ddoc.split('/')[1] for ddoc in ddocs]))

@database_rule
def check_db_admins(db, log, cache):
    _, _, security = db.resource('_security').get_json()

    db_admins = security.get('admins', {})
    db_admins.setdefault('names', [])
    db_admins.setdefault('roles', [])

    if not (db_admins['names'] or db_admins['roles']):
        return

    users = cache.get('users')
    if not users:
        log.error('Unable to audit database admins: user list is not available')
        return

    actual_admins = {'names': [], 'roles': []}
    for _id, doc in users.items():
        if doc['name'] in db_admins['names']:
            actual_admins['names'].append(doc['name'])
        if doc['roles'] in db_admins['roles']:
            actual_admins['roles'].append(doc['name'])

    diff = set(actual_admins['names']) ^ set(db_admins['names'])
    total = len(db_admins['names'])
    if total and not diff:
        log.info('Found %d database administrators, all are actual', total)
    elif total:
        missed = len(diff)
        log.error('Found %d database administrators, but %d of them are missed',
                 total, missed)
        log.error('Using next names anyone could easily become database'
                  ' administrator: %s', ','.join(diff))
    if db_admins['names']:
        log.info('Database administrators: %s', ','.join(db_admins['names']))

    diff = set(actual_admins['roles']) ^ set(db_admins['roles'])
    total = len(db_admins['roles'])
    if total and not diff:
        log.info('Found %d database administrator roles, all are actual', total)
    elif total:
        missed = len(diff)
        log.error('Found %d database administrator roles, but %d of them are'
                 ' missed', total, missed)
        log.error('Using next roles anyone could easily become database'
                  ' administrator: %s', ','.join(diff))
    if db_admins['roles']:
        log.info('Database administrator roles: %s',
                  ','.join(db_admins['roles']))

@database_rule
def check_db_members(db, log, cache):
    _, _, security = db.resource('_security').get_json()

    db_members =  security.get('readers', {})
    db_members.setdefault('names', [])
    db_members.setdefault('roles', [])

    if not (db_members['names'] or db_members['roles']):
        return

    users = cache.get('users')
    if not users:
        log.error('Unable to audit database members: user list is not available')
        return

    actual_members = {'names': [], 'roles': []}
    for _id, doc in users.items():
        if doc['name'] in db_members['names']:
            actual_members['names'].append(doc['name'])
        if doc['roles'] in db_members['roles']:
            actual_members['roles'].append(doc['roles'])


    diff = set(actual_members['names']) ^ set(db_members['names'])
    total = len(db_members['names'])
    if not diff:
        log.info('Found %d database members, all are actual', total)
    else:
        missed = len(diff)
        log.warn('Found %d database members, but %d of them are missed',
                 total, missed)
        log.warn('Using next names anyone could easily become database'
                  ' member: %s', ','.join(diff))
    if db_members['names']:
        log.info('Database member users: %s', ','.join(db_members['names']))

    diff = set(actual_members['roles']) ^ set(db_members['roles'])
    total = len(db_members['roles'])
    if total and not diff:
        log.info('Found %d database member roles, all are actual', total)
    elif total:
        missed = len(diff)
        log.warn('Found %d database member roles, but %d of them are missed',
                 total, missed)
        log.warn('Using next roles anyone could easily become database'
                  ' member: %s', ','.join(diff))
    if db_members['roles']:
        log.info('Database member roles: %s', ','.join(db_members['roles']))

@ddoc_rule
def check_ddoc_language(ddoc, log, cache):
    if 'language' not in ddoc:
        log.error('Language is not explicitly defined')
        return
    log.info('Design language used: %s', ddoc['language'])

    config = cache.get('config')
    if config is None:
        return

    if ddoc['language'] not in config['query_servers']:
        log.error('There is not query servers to handle ddoc language %s.'
                  ' Possible languages are: %s',
                  ddoc['language'], ', '.join(config['query_servers']))

@ddoc_rule
def check_ddoc_functions(ddoc, log, cache):
    for key in ['views', 'shows', 'lists', 'updates']:
        if ddoc.get(key):
            log.info('Found %d %s functions: %s',
                     len(ddoc[key]), key[:-1], ', '.join(ddoc[key]))

@ddoc_rule
def check_ddoc_validate_func(ddoc, log, cache):
    if 'validate_doc_update' not in ddoc:
        log.warn('validate_doc_update function missed')
    else:
        log.info('validate_doc_update function exists')
