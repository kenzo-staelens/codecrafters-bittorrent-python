import struct
import socket
import random
import string

class Packet:
    def build(self):
        raise NotImplementedError(f"base packet {self.__class__.__name__} does not implement build")

    @classmethod
    def parse(cls,data):
        raise NotImplementedError(f"base packet {self.__class__.__name__} does not implement parse")

class Query(Packet):
    key = "q"

class Response(Packet):
    key = "r"
    
    @classmethod
    def compact_nodes(cls,nodes):
        n = len(nodes)
        def helper():
            nonlocal nodes
            for _node in nodes:
                ip = socket.inet_aton(_node.address[0])
                yield _node._id.to_bytes(20, 'big')
                yield ip
                yield _node.address[1]
        return struct.pack(">"+"20s4sH"*n,*list(helper()))
    
    @classmethod
    def compact_values(cls,values):
        return [struct.pack(">LH",value) for value in values]
    
    @classmethod
    def uncompact_nodes(cls,nodes):
        if isinstance(nodes,str):
            nodes = nodes.encode()
        n = int(len(nodes)/26)
        unpacked = struct.unpack(">"+"20s4sH"*n,nodes)
        return [(
            int.from_bytes(unpacked[i]),
            (socket.inet_ntoa(unpacked[i+1]),
            unpacked[i+2])) for i in range(0, len(unpacked)-1,3)]
    
    @classmethod
    def uncompact_values(cls,values):
        #sometimes a string slips through in decoding
        values = [x.encode() if isinstance(x,str) else x for x in values]
        unpacked = [struct.unpack(">4sH",value) for value in values]
        return [(socket.inet_ntoa(address[0]), address[1])
            for address in unpacked]

class Error(Packet):
    key = "e"

def base_query(instance,args=None):
    
    packet = {
        instance.key:instance.name,
        't':''.join([random.choice(string.ascii_letters) for _ in range(2)]),
        'y':instance.key
    }
    instance.transaction = packet['t']
    if args is not None:
        packet = {'a':args} | packet
    return packet

def base_response(instance,resp,args=None):
    packet = {
        't':instance.transaction,
        'y':instance.key,
        instance.key:resp
    }
    if args is not None:
        packet |= args
    return packet