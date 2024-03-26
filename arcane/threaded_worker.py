from arcane.base_object import BaseObject
from threading import Thread, Event, get_ident
from queue import Queue, Empty
import time

def api(func):
    '''Method decorator that sends execution contexts to the thread in a ThreadedWorker.'''
    def _wrapper(self, *args, sync_timeout: float=None, **kwargs):
        if not sync_timeout:
            self.mailbox.put((func, args, kwargs))
        else:
            # We need a way to have the 'func' execute in the ThreadedWorker's thread and return the result to the callers thread
            # We do this by having the worker send it back via a temporary shared queue.
            queue = Queue()
            def _get_result():
                result = func(*args, **kwargs)
                queue.put(result)
            
            self.mailbox.put((_get_result, (), {}))

            try:
                # Return result when it's available or give up after sync_timeout
                return queue.get(timeout=sync_timeout)
            except Empty:
                raise TimeoutError

    return _wrapper


class ThreadedWorker(BaseObject):
    def __init__(self) -> None:
        self.mailbox     = Queue()
        self.event       = Event()
        self.thread      = Thread(target=self._run, daemon=True)
        self.thread.start()
        self.__init_loops()


    def __del__(self):
        '''Function used by python internals when object is deleted.'''
        self.close()


    def close(self):
        self.event.set()


    @api
    def sleep(self, sleep_time):
        time.sleep(sleep_time)


    @api
    def _set(self, name, value):
        object.__setattr__(self, name, value)


    def __init_loops(self):
        for attr_name in dir(self):
            attr = getattr(self, attr_name)
            if callable(attr):
                if hasattr(attr, '_loop_init'):
                    attr._loop_init(self)
                
                if hasattr(attr, '_sub_init'):
                    event_man, event = attr._sub_init
                    event_man.subscribe(event, attr)


    def __setattr__(self, name: str, value: object) -> None:
        # Fixes the race condition in initialization
        if hasattr(self, "thread") and get_ident() != self.thread.ident:
            self._set(name, value)
        else:
            object.__setattr__(self, name, value)


    def _run(self):
        while not self.event.is_set():
            try:
                func, args, kwargs = self.mailbox.get(timeout=150e-3)
                func(self, *args, **kwargs)
            except Empty:
                pass
