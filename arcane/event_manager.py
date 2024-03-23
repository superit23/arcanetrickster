from arcane.threaded_worker import ThreadedWorker, api

class EventManager(ThreadedWorker):
    def __init__(self):
        self.subscriptions = {}
        super().__init__()
    

    @api
    def subscribe(self, event: 'Enum', callback):
        if not event in self.subscriptions:
            self.subscriptions[event] = []

        self.log.info(f"Appending callback for {event}")
        self.subscriptions[event].append(callback)

    @api
    def trigger_event(self, event: 'Enum', *args, **kwargs):
        if not event in self.subscriptions:
            self.subscriptions[event] = []
        
        self.log.info(f"Event occurred: {event} {args}")
        for subscriber in self.subscriptions[event]:
            subscriber(*args, **kwargs)


_event_man = EventManager()

def trigger_event(event: 'Enum', *args, **kwargs):
    _event_man.trigger_event(event, *args, **kwargs)


def on_event(event: 'Enum'):
    def _wrapper(func):
        func._sub_init = (_event_man, event)
        return func

    return _wrapper
