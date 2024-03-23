from functools import lru_cache
import logging
logging.basicConfig(format='%(asctime)s - %(name)s(%(thread)d) [%(levelname)s] %(message)s', level=logging.INFO)

class BaseObject(object):

    @property
    @lru_cache(1)
    def log(self):
        return logging.getLogger(self.__class__.__name__)

