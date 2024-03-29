from functools import lru_cache
from rich.logging import RichHandler
import logging
# logging.basicConfig(format='%(asctime)s - %(name)s(%(thread)d) [%(levelname)s] %(message)s', level=logging.DEBUG, handlers=[RichHandler()])
logging.basicConfig(format='%(name)s(%(thread)d) %(message)s', handlers=[RichHandler()])


class BaseObject(object):

    @property
    @lru_cache(1)
    def log(self):
        return logging.getLogger(f'{self.__class__.__module__}.{self.__class__.__name__}')
