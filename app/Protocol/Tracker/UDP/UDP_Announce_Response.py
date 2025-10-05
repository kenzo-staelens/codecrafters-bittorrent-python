import struct
import socket

from .Action import Action

class AnnounceResponse:
    def __init__(self, data, transaction_id):
        if len(data)<20:
            raise ValueError(f"data too short: {len(data)}")
        self.action,self.transaction_id,self.interval,leechers,seeders=struct.unpack(">I 4s I I I",data[:20])
        if self.action!=Action.Announce or self.transaction_id!=transaction_id:
            raise ValueError("announce invalid response",self.action,self.transaction_id==transaction_id)
        temp = [struct.unpack(">IH",data[20+offset:20+offset+6]) for offset in range(0,len(data)-20,6)] # was >4IH and jump of 26
        self.peers = [(socket.inet_ntoa(struct.pack('!L', data[0])),data[1]) for data in temp]
    
    def __repr__(self):
        return f'{self.interval} {self.peers}'