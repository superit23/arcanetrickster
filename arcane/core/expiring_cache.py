from arcane.core.threaded_worker import ThreadedWorker, api, trigger_event
from arcane.core.events import ExpiringCacheManagerEvent, ExpiringCacheEvent
from arcane.core.runtime import RUNTIME, api
import time

class ExpiringCacheManager(ThreadedWorker):
    def __init__(self) -> None:
        self.object_timer_map = {}
        super().__init__()
        self._process_timers()
    
    @api
    def add_timer(self: "ExpiringCacheManager", cache: "ExpiringCache", sleep_time: float, key: object) -> None:
        expire_time = time.time() + sleep_time
        if (cache,key) in self.object_timer_map:
            #dicts in python3.6+ preserve insertion order -- reinsert after delete
            trigger_event(ExpiringCacheManagerEvent.CACHE_ITEM_UPDATED, key, cache[key], expire_time)
            del self.object_timer_map[cache,key]
     
        self.object_timer_map[cache,key] = expire_time
    

    @api
    def del_timer(self: "ExpiringCacheManager", cache: "ExpiringCache", key: object) -> None:
        del self.object_timer_map[cache,key]


    @api
    def _process_timers(self: "ExpiringCacheManager"):
        current_time = time.time()
        for (cache, key), expiration in self.object_timer_map.items():

            if expiration < current_time:
                trigger_event(ExpiringCacheManagerEvent.CACHE_ITEM_EXPIRED, (cache,key), cache[key], current_time)
                del cache[key] 
            if expiration > current_time:
                #dict preserve insertion order, if we find something earlier than time.time() then break early
                break 
        self.sleep(5e-3)
        self._process_timers()


class ExpiringCache(object):
    def __init__(self, expire_time: float, *arg, **kw):
      self.expire_time = expire_time
      self.dict        = {}

    def __repr__(self) -> str:
        return str(self.dict)

    def __getitem__(self: "ExpiringCache", key: object) -> object:
        return self.dict.__getitem__(key)
    

    def __setitem__(self: "ExpiringCache", key: object, value: object) -> None:
        RUNTIME.expiring_cache_manager.add_timer(self,self.expire_time, key)
        self.dict.__setitem__(key,value)
        trigger_event(ExpiringCacheEvent.ITEM_ADDED, key, self[key], self.expire_time)


    def __delitem__(self: "ExpiringCache", key: object) -> None:
        RUNTIME.expiring_cache_manager.del_timer(self,key)
        trigger_event(ExpiringCacheEvent.ITEM_REMOVED, key, self[key], time.time())
        self.dict.__delitem__(key)
   

if __name__ == '__main__':
    cache = ExpiringCache(10)
    for idx in range(0,50):
        time.sleep(1)
        cache[idx] = idx * idx
        if idx == 10:
            cache[idx] = idx * idx
        print(cache)
    
    
    
