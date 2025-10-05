import random
import struct
import functools

from .Action import Action
from Protocol.Tracker import Event

def setter(func):
    @functools.wraps(func)
    def wrapped(self, value):
        if value is None:
            raise ValueError("value cannot be None")
        func(self,value)

class Announce:
    def __init__(self, connection_id):
        self.connection_id = connection_id
        self.action = Action.Announce
        self.transaction_id = random.randbytes(4)
        self.__infohash = None
        self.__peer_id = None
        self.ip = 0
        self.event = Event.Zero
        self.key = bytes(4)
        self.numwant = -1
        self.port = 6881
        self.__downloaded = 0
        self.uploaded = 0
        self.left = 1024*16
    
    @property
    def infohash(self):
        return self.__infohash
    
    @infohash.setter
    def infohash(self, infohash):
        if infohash is None:
            raise ValueError("infohash cannot be set to none")
        if self.__peer_id is not None:
            raise ValueError("cannot override infohash")
        self.__infohash = infohash
    
    @property
    def peer_id(self):
        return self.__peer_id
    
    @peer_id.setter
    def peer_id(self, peer_id):
        if peer_id is None:
            raise ValueError("peer_id cannot be set to none")
        if self.__peer_id is not None:
            raise ValueError("cannot override peer id")
        self.__peer_id = peer_id
    
    def set_uploaded(self, uploaded):
        if uploaded<0 or type(uploaded)!=int:
            raise ValueError("uploaded must be a positive integer")
        self.uploaded = uploaded
    
    @property
    def downloaded(self):
        return self.__downloaded
    
    @downloaded.setter
    def downloaded(self, downloaded):
        if downloaded<0 or type(downloaded)!=int:
            raise ValueError("downloaded must be a positive integer")
        self.__downloaded = downloaded
    
    def set_left(self, left):
        if uploaded<0 or type(uploaded)!=int:
            raise ValueError("left must be a positive integer")
        self.left = left
    
    def set_event(self, event):
        self.event = event
    
    def build(self):
        return struct.pack(
            ">8s I 4s 20s 20s Q Q Q I I 4s i H", # was >8s I 4s 20s 20s Q Q Q I I 8s i H
            self.connection_id, self.action, self.transaction_id, self.infohash,
            self.peer_id, self.downloaded, self.left, self.uploaded,
            self.event, self.ip, self.key, self.numwant, self.port
        )