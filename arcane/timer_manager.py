from arcane.threaded_worker import ThreadedWorker, api
from arcane.utilities import binary_search_list
import time

class TimerManager(ThreadedWorker):
    def __init__(self) -> None:
        self.timers = []
        super().__init__()
        self._process_timers()


    @api
    def add_timer(self, sleep_time, callback: 'function', params):
        self.timers.append((time.time() + sleep_time, callback, params))


    @api
    def _process_timers(self):
        idx = binary_search_list(self.timers, time.time(), key=lambda item: item[0], fuzzy=True)

        for _, callback, (other_self, args, kwargs) in self.timers[:idx]:
            callback(other_self, *args, **kwargs)

        del self.timers[:idx]

        self.sleep(5e-3)
        self._process_timers()
