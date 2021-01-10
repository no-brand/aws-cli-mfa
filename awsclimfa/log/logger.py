# -*- coding: utf-8 -*-

import os
import yaml
import logging
from logging import config


class Logger:
    def __init__(self, level=logging.DEBUG):
        with open('{}/config.yaml'.format(os.path.dirname(__file__)), 'r') as f:
            dic = yaml.safe_load(f.read())
            config.dictConfig(dic)
        self.__logger = logging.getLogger('aws-cli-mfa')
        self.__logger.setLevel(level)

    @property
    def logger(self):
        return self.__logger
