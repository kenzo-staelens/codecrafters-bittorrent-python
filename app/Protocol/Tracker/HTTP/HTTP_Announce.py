import functools

from Protocol.Tracker import Event

def setter(func):
    @functools.wraps(func)
    def wrapped(self, value):
        if value is None:
            raise ValueError("value cannot be None")
        func(self,value)

class Announce:
    def __init__(self):
        self.__infohash = None
        self.__peer_id = None
        self.ip = None
        self.port = 6881
        self.uploaded = 0
        self.__downloaded = 0
        self.left = 10*1024
        self.event = Event.Absent
    
    @property
    def infohash(self):
        return self.__infohash
    
    @infohash.setter
    def infohash(self, infohash):
        if self.peer_id is not None:
            raise ValueError("cannot override infohash")
        self.__infohash = infohash
    
    @property
    def peer_id(self):
        return self.__peer_id
    
    @peer_id.setter
    def peer_id(self, peer_id):
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
        if self.infohash is None or self.peer_id is None:
            raise ValueError("missing infohash or peer_id")
        prepared = {
            'info_hash':self.infohash,
            'peer_id':self.peer_id,
            'ip':self.ip,
            'port':self.port,
            'uploaded':self.uploaded,
            'downloaded':self.__downloaded,
            'left': str(self.left),
            'event':self.event,
            'compact':1
        }
        return {x[0]:x[1] for x in prepared.items() if x is not None}