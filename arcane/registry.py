from arcane.threaded_worker import ThreadedWorker
from arcane.events import RuntimeEvent
from arcane.runtime import api, on_event, loop

class Registry(ThreadedWorker):
    def __init__(self):
        self.map = {}
        super().__init__()
    

    @api
    def register(self, name: str, worker: ThreadedWorker):
        self.map[name] = worker


    @loop(5)
    def get_status(self):
        for v in self.map.values():
            v.status()


    # @on_event(RuntimeEvent.STATUS)
    # def handle_status(self, worker: ThreadedWorker, status: str):
    #     self.log.info(status)
