from Protocol.Base import Parseable

class Bitfield(Parseable):
    packet_id = 5
    
    def __init__(self,bits):
        self.bits = bits
    
    @classmethod
    def parse(cls,data):
        return Bitfield(data)