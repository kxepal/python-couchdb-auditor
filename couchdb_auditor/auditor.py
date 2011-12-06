# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import re

_RULES = {
    'server': []
}

def server_rule(func):
    _RULES['server'].append(func)
    return func

def get_rules(name):
    return _RULES[name]

def audit_server(server, log):
    for rule in get_rules('server'):
        rule(server, log)

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
