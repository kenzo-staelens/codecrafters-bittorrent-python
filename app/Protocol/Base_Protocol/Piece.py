import struct
from Protocol.Base import Parseable

class Piece(Parseable):
    packet_id = 7
    
    def __init__(self, index, begin, content):
        self.index = index
        self.begin = begin
        self.content = content
    
    @classmethod
    def parse(cls,data):
        index, begin = struct.unpack(">II",data[:8])
        data = data[8:]
        return Piece(index, begin, data)
