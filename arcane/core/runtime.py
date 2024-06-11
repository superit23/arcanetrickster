from functools import lru_cache
from queue import Queue, Empty
from enum import Enum, auto

class _Runtime(object):
    @property
    @lru_cache(1)
    def timer_manager(self):
        from arcane.core.timer_manager import TimerManager
        return TimerManager()


    @property
    @lru_cache(1)
    def event_manager(self):
        from arcane.core.event_manager import EventManager
        return EventManager()


    @property
    @lru_cache(1)
    def expiring_cache_manager(self):
        from arcane.core.expiring_cache import ExpiringCacheManager
        return ExpiringCacheManager()


RUNTIME = _Runtime()

def loop(sleep_time):
    def _outwrapper(func: 'function'):
        api_func = api(func)

        def _wrapper(self, *args, **kwargs):
            api_func(self, *args, **kwargs)
            RUNTIME.timer_manager.add_timer(sleep_time, _wrapper, (self, args, kwargs))

        # Initialize the loop
        api_func._loop_init = _wrapper
        return api_func

    return _outwrapper



def trigger_event(event: 'Enum', *args, **kwargs):
    RUNTIME.event_manager.trigger_event(event, *args, **kwargs)


def on_event(event: 'Enum', filter_func=None):
    def _wrapper(func):
        func._sub_init = (RUNTIME.event_manager, event, filter_func)
        return func

    return _wrapper



def api(func):
    '''Method decorator that sends execution contexts to the thread in a ThreadedWorker.'''
    def _wrapper(self, *args, sync_timeout: float=None, do_after: float=None, **kwargs):
        if sync_timeout:
            # We need a way to have the 'func' execute in the ThreadedWorker's thread and return the result to the callers thread
            # We do this by having the worker send it back via a temporary shared queue.
            queue = Queue()
            def _get_result(self):
                result = func(self, *args, **kwargs)
                queue.put(result)

            self.mailbox.put((_get_result, (), {}))

            try:
                # Return result when it's available or give up after sync_timeout
                return queue.get(timeout=sync_timeout)
            except Empty:
                raise TimeoutError
        
        elif do_after:
            RUNTIME.timer_manager.add_timer(do_after, func, (self, args, kwargs))

        else:
            self.mailbox.put((func, args, kwargs))

    return _wrapper
