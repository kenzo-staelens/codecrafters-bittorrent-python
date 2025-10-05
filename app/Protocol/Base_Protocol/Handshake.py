import struct
from Protocol.Base import Sendable, Parseable

class Handshake(Sendable,Parseable):
    def __init__(self,reserved,infohash, peer_id,*,name=b"BitTorrent protocol"):
        self.name = name
        self.name_length = struct.pack(">B",len(name))
        self.reserved = reserved
        self.infohash = infohash
        self.peer_id = peer_id
    
    def compile_proto(self,_):
        self.proto = self.name_length + self.name + self.reserved + self.infohash + self.peer_id
    
    @classmethod
    def parse(self,data):
        name_len = data[0]
        name = data[1:1+name_len]
        reserved = data[-48:-40]
        infohash = data[-40:-20]
        peer = data[-20:]
        
        return Handshake(reserved,infohash,peer,name=name)
        
    #outlier packet, different parsing
    @classmethod
    def read_packet(self, socket):
        proto_name_len = socket.recv(1)[0]
        proto_name = socket.recv(proto_name_len)
        reserved = socket.recv(8)
        infohash = socket.recv(20)
        peer = socket.recv(20)
        
        return Handshake(reserved,infohash,peer,name=proto_name)
        # return {"name":proto_name, "reserved":reserved,"infohash":infohash,"peer":peer}