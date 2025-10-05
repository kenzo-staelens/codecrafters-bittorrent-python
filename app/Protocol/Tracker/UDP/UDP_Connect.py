import random
import struct

from .Action import Action

class Connect:
    magic = 0x41727101980
    def __init__(self):
        self.transaction_id = random.randbytes(4)
        self.action = Action.Connect
    
    def build(self):
        return struct.pack(">QI4s",self.magic,self.action,self.transaction_id)
