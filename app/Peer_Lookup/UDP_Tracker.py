import random
import struct
import socket
import time

from .Base_Tracker import Base_Tracker

# https://www.bittorrent.org/beps/bep_0015.html

class UDP_Tracker(Base_Tracker):
    magic = 0x41727101980
    def __init__(self, url):
        super().__init__(url)
        try:
            self.connection_id = self.connect()
            self.connected=True
        except:
            self.connected = False
        self.interval = (0,0)
        self.cache = []
    
    def get_peers(self,infohash,info=None):
        if sum(self.interval)<time.time():
            self.cache = self.announce(infohash,self._id,info=info)
        return self.cache
    
    def connect(self):
        transaction_id = random.randbytes(4)
        data = struct.pack(">QI4s",self.magic,0,transaction_id)
        # data = struct.pack(">QII",self.magic,0,transaction_id)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(data,self.address)
        data, addr = sock.recvfrom(1024)
        if len(data)<16:
            raise ValueError(f"data too short: {len(data)}")
        a,i,connection_id = struct.unpack(">I4s8s",data)
        # a,i,connection_id = struct.unpack(">II8s",data)
        if a!=0 or i!=transaction_id:
            raise ValueError("udp connect invalid response",a,i==transaction_id)
        return connection_id
    
    def announce(self,infohash,peer_id,info=None):
        if not self.connected:
            return []
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', 0))
        transaction_id = random.randbytes(4)
        key = random.randbytes(4)
        data = struct.pack(
            ">8s I 4s 20s 20s Q Q Q I I 8s i H",
            self.connection_id,
            1,
            transaction_id,
            infohash,
            peer_id,
            0,
            info['left'] if info is not None else 16384,
            0, # uploaded
            0, # event
            0, # ip
            key,
            -1,
            # sock.getsockname()[1]
            0
        )
        sock.sendto(data,self.address)
        data, addr = sock.recvfrom(1024)
        if len(data)<20:
            raise ValueError(f"data too short: {len(data)}")
        a,i,interval,l,s=struct.unpack(">I 4s I I I",data[:20])
        if a!=1 or i!=transaction_id:
            print(data)
            raise ValueError("announce invalid response",a,i==transaction_id)
        self.interval = (time.time(),interval)
        peers = [struct.unpack(">4IH",data[20+offset:20+offset+6]) for offset in range(0,len(data)-20,26)]
        # print(peers)
        return peers
    
    def get_peers_queue(self, infohash, peer_id, info=None,live_queue=None):
        if live_queue is None:
            raise ValueError("live queue required")
        peers = self.get_peers(infohash,peer_id,info)
        for peer in peers:
            live_queue.put(peer)

if __name__ == "__main__":
    trs = ["udp://tracker.leechers-paradise.org:6969",
        "udp://zer0day.ch:1337",
        "udp://open.demonii.com:1337",
        "udp://tracker.coppersurfer.tk:6969",
        "udp://exodus.desync.com:6969"
    ]
    peer_id = random.randbytes(20)
    infohash = bytes.fromhex("954B7FE36E45AA4326A99F93E66AAC0F607D0F4B")
    for trd in trs:
        try:
            tr = UDP_Tracker(trd)
            peers = tr.get_peers(infohash,peer_id)
            print(peers)
        except Exception as e:
            # print(e)
            pass