from arcane.core.threaded_worker import ThreadedWorker, api
from enum import Enum, auto
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


    def wait_for_match(self, event, filter_func, timeout: float=None):
        queue = Queue()
        self._add_to_sync_queue(event, filter_func, queue)
        return queue.get(timeout=timeout)


    def _check_init_event(self, event):
        if not event in self.subscriptions:
            self.subscriptions[event]  = []
            self.sync_listeners[event] = []


    @api
    def _add_to_sync_queue(self, event, filter_func, queue):
        if not event in self.sync_listeners:
            self.sync_listeners[event] = []

        self.sync_listeners[event].append((filter_func, queue))


    @api
    def subscribe(self, event: 'Enum', callback, filter_func=None):
        self._check_init_event(event)

        self.log.info(f"Appending callback for {event} for {callback}")
        self.subscriptions[event].append((filter_func, callback))


    @api
    def trigger_event(self, event: 'Enum', *args, **kwargs):
        self._check_init_event(event)

        self.log.info(f"Event occurred: {event} {args}", extra={"event": event})
        for filter_func, subscriber in self.subscriptions[event]:
            if not filter_func or filter_func(*args, **kwargs):
                subscriber(*args, **kwargs)

        if event in self.sync_listeners:
            for filter_func, queue in self.sync_listeners[event]:
                if filter_func(event, *args, **kwargs):
                    queue.put((args, kwargs))


            self.sync_listeners[event] = []
