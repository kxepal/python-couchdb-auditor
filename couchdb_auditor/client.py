# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import couchdb

class Server(couchdb.Server):

    def session(self):
        _, _, session = self.resource('_session').get_json()
        return session
