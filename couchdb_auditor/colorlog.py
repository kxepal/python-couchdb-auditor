# -*- coding: utf-8 -*-
#
# Copyright (C) 2011 Alexander Shorin
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#

import logging

class ColoredFormatter(logging.Formatter):

    def __init__(self, fmt=None, datefmt=None):
        self.colors = {
            'CRITICAL': '\x1b[1;31m',
            'ERROR': '\x1b[1;31m',
            'INFO': '\x1b[1;32m',
            'WARN': '\x1b[1;33m',
            'WARNING': '\x1b[1;33m',
            'DEBUG': '\x1b[1;37m',
        }
        self.reset = '\033[0m'
        self.bold = '\033[1m'
        super(ColoredFormatter, self).__init__(fmt, datefmt)

    def format(self, record):
        record.reset = self.reset
        record.bold = self.bold
        levelname = record.levelname
        if levelname in self.colors:
            color = self.colors[levelname]
            record.levelname = ''.join((color, levelname, self.reset))
        return logging.Formatter.format(self, record)
