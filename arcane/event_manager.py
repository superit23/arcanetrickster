from arcane.threaded_worker import ThreadedWorker, api
from queue import Queue
import logging


class ArcaneEventFilter(logging.Filter):
    def __init__(self, name: str = "", allowlist_events: set=None) -> None:
        self.allowlist_events = allowlist_events or set()
        super().__init__(name)


    def filter(self, record: logging.LogRecord) -> bool | logging.LogRecord:
        if "event" in record.__dict__:
            if record.event in self.allowlist_events:
                return super().filter(record)
            else:
                return False
        else:
            return super().filter(record)



class EventManager(ThreadedWorker):
    def __init__(self):
        self.subscriptions  = {}
        self.sync_listeners = {}
        self.log_filter = ArcaneEventFilter()
        super().__init__()

        self.log.addFilter(self.log_filter)



    def wait_for_match(self, event, match_func):
        queue = Queue()
        self._add_to_sync_queue(event, match_func, queue)
        return queue.get()


    def _check_init_event(self, event):
        if not event in self.subscriptions:
            self.subscriptions[event] = []
            self.sync_listeners[event] = []
    
    @api
    def _add_to_sync_queue(self, event, match_func, queue):
        if not event in self.sync_listeners:
            self.sync_listeners[event] = []

        self.sync_listeners[event].append((match_func, queue))


    @api
    def subscribe(self, event: 'Enum', callback):
        self._check_init_event(event)

        self.log.info(f"Appending callback for {event}")
        self.subscriptions[event].append(callback)


    @api
    def trigger_event(self, event: 'Enum', *args, **kwargs):
        self._check_init_event(event)

        self.log.info(f"Event occurred: {event} {args}", extra={"event": event})
        for subscriber in self.subscriptions[event]:
            subscriber(*args, **kwargs)
        
        if event in self.sync_listeners:
            for match_func, queue in self.sync_listeners[event]:
                if match_func(event, *args, **kwargs):
                    queue.put((args, kwargs))


            self.sync_listeners[event] = []
            


_event_man = EventManager()

def trigger_event(event: 'Enum', *args, **kwargs):
    _event_man.trigger_event(event, *args, **kwargs)


def on_event(event: 'Enum'):
    def _wrapper(func):
        func._sub_init = (_event_man, event)
        return func

    return _wrapper
