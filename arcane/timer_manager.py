from arcane.threaded_worker import ThreadedWorker, api
from arcane.utilities import binary_search_list
import time

class TimerManager(ThreadedWorker):
    def __init__(self) -> None:
        self.timers = []
        super().__init__()


    def add_timer(self, sleep_time, callback, sig):
        self.timers.append((time.time() + sleep_time, callback, sig))
        self.timers.sort(key=lambda item: item[0])


    def _run(self):
        while not self.event.is_set():
            time.sleep(1e-3)
            idx = binary_search_list(self.timers, time.time(), key=lambda item: item[0], fuzzy=True)

            for _, callback, (s, args, kwargs) in self.timers[:idx]:
                callback(s, *args, **kwargs)

            del self.timers[:idx]


_timer_man = TimerManager()

def loop(sleep_time):
    def _outwrapper(func):
        api_func = api(func)

        def _wrapper(self, *args, **kwargs):
            api_func(self, *args, **kwargs)
            _timer_man.add_timer(sleep_time, _wrapper, (self, args, kwargs))

        # Initialize the loop
        api_func._loop_init = _wrapper
        return api_func

    return _outwrapper

