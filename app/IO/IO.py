from queue import Queue
from threading import Thread

class IO:
    def __init__(self, peer):
        self.peer = peer
        self.thread = Thread(target = self.work)
        self.packetQueue = Queue()
    
    def start(self):
        self.thread.start()
    
    def work(self):
        raise NotImplementedError("work not implemented in base class")