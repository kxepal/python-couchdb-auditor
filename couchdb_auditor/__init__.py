# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import couchdb
import getopt
import logging
import os
import socket
import sys
from getpass import getpass
from couchdb.http import extract_credentials, HTTPError
from couchdb_auditor import auditor
from couchdb_auditor.colorlog import ColoredFormatter

__version__ = '0.1'

_VERSION = 'couchdb-auditor %s' % __version__

_HELP = """Usage: %(name)s [OPTIONS] URL

Arguments:

  URL              CouchDB server URL in next form:
                   http[s]://[user[:password]@]host[:port]
                   Note that setting password in URL will make it visible in
                   shell history.

Options:

  --version        Display version information and exit.
  -h, --help       Display a this help message and exit.
  -u, --user=      Set CouchDB user that would inspect server
                   User could be also defined in URL.
                   Password will be requested.
  -d, --database   Audit database by specified URL, not server.

""" % dict(name=os.path.basename(sys.argv[0]))

_NO_URL = """URL argument must be specified. See --help for more information.
"""

_USER_DUPLICATE = """Multiple users defined, couldn't decide which one to use:
%s or %s
"""

class NiceFormatter(ColoredFormatter):
    def __init__(self, fmt, indent=0):
        fmt = '%(reset)s' + '  ' * indent + fmt
        super(NiceFormatter, self).__init__(fmt)

    def format(self, record):
        record.funcName = '[%s]' % record.funcName
        levelname = record.levelname
        if levelname in self.colors:
            color = self.colors[levelname]
            levelname = levelname[0] * 2
            record.levelname = '[%s]' % ''.join((color, levelname, self.reset))
        return super(NiceFormatter, self).format(record)

def get_logger(name, level=logging.DEBUG, indent=0):
    fmt = '%(levelname)-8s %(funcName)-24s  %(message)s'
    instance = logging.Logger('couchdb.audit.%s' % name, level)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(NiceFormatter(fmt, indent=indent))
    instance.addHandler(handler)
    instance.propagate = False
    return instance

def run(url, credentials, target='server'):
    root = logging.Logger('couchdb.audit')
    handler = logging.StreamHandler(sys.stdout)
    root.addHandler(handler)

    def audit_server(url, credentials):
        server = couchdb.Server(url)
        server.resource.credentials = credentials
        root.info(' * %s', server.resource.url)

        try:
            server.resource.head()
        except (HTTPError, socket.error), err:
            sys.stdout.write('%s: %s\n' % (err.__class__.__name__, err))
            sys.stdout.flush()
            sys.exit(1)

        cache = {}
        log = get_logger('couchdb.audit.server')
        auditor.audit_server(server, log, cache)

        try:
            dblist = list(server)
        except HTTPError, err:
            sys.stdout.write('Unable to get database list.\n')
            sys.stdout.write('%s: %s\n' % (err.__class__.__name__, err.args[0][1]))
            sys.stdout.flush()
            sys.exit(1)

        for dbname in dblist:
            url = server.resource(dbname).url
            audit_database(url, credentials, name=None, cache=cache)

    def audit_database(url, credentials, name=None, cache=None):
        if cache is None:
            cache = {}
        log = get_logger('couchdb.audit.database')
        db = couchdb.Database(url, name=name)
        db.resource.credentials = credentials
        root.info(' * %s', db.resource.url)
        auditor.audit_database(db, log, cache)

        try:
            rows = db.view('_all_docs', startkey='_design/',  endkey='_design0')
            rows = list(rows)
        except HTTPError, err:
            log.critical('Unable to get design documents list: %s',
                         err.args[0][1])
            return

        for row in rows:
            root.info(' * %s', db.resource(*row.id.split('/')).url)
            log = get_logger('couchdb.audit.ddoc')
            ddoc = db[row.id]
            auditor.audit_ddoc(ddoc, log, cache)

    if target == 'server':
        audit_server(url, credentials)
    elif target == 'database':
        audit_database(url, credentials)

    return 0

def main():
    try:
        options, arguments = getopt.gnu_getopt(
            sys.argv[1:], 'hvu:d',
            ['version', 'help', 'user=', 'database']
        )
    except getopt.GetoptError, err:
        sys.stdout.write(('%s\n\n' % err).capitalize())
        sys.stdout.write(_HELP)
        sys.stdout.flush()
        sys.exit(1)
    message = None

    if not arguments:
        sys.stdout.write(_NO_URL)
        sys.stdout.flush()
        sys.exit(1)

    target = 'server'
    url = arguments[0]
    if not url.startswith('http://'):
        url = 'http://' + url
    _, credentials = extract_credentials(url)
    if credentials:
        credentials = list(credentials)

    for option, value in options:
        if option in ['--version']:
            message = _VERSION
        elif option in ['-h', '--help']:
            message = _HELP
        elif option in ['-u', '--user']:
            if credentials and credentials[0] != value:
                message = _USER_DUPLICATE % (credentials[0], value)
            elif not credentials:
                credentials = [value]
        elif option in ['-d', '--database']:
            target = 'database'

    if message:
        sys.stdout.write(message)
        sys.stdout.flush()
        sys.exit(0)

    if credentials and len(credentials) == 1:
        credentials.append(getpass('Enter password for %s: ' % credentials[0]))
        credentials = tuple(credentials)

    sys.exit(run(url, credentials, target))

if __name__ == '__main__':
    main()
