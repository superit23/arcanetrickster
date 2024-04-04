from arcane.threaded_worker import ThreadedWorker, api
from arcane.utilities import binary_search_list
import time

class TimerManager(ThreadedWorker):
    def __init__(self) -> None:
        self.timers = []
        super().__init__()


    def add_timer(self, sleep_time, callback: 'function', params):
        self.timers.append((time.time() + sleep_time, callback, params))
        self.timers.sort(key=lambda item: item[0])


    def _run(self):
        while not self.event.is_set():
            time.sleep(1e-3)
            idx = binary_search_list(self.timers, time.time(), key=lambda item: item[0], fuzzy=True)

            for _, callback, (other_self, args, kwargs) in self.timers[:idx]:
                callback(other_self, *args, **kwargs)

            del self.timers[:idx]
