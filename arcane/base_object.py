from functools import lru_cache
from rich.logging import RichHandler
from copy import copy
import logging
logging.basicConfig(format='%(name)s(%(thread)d) %(message)s', handlers=[RichHandler()])


class BaseObject(object):

    @property
    @lru_cache(1)
    def log(self):
        return logging.getLogger(f'{self.__class__.__module__}.{self.__class__.__name__}')

    def copy(self):
        return copy(self)
    