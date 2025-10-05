import struct

from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder
from Protocol.Base import Sendable,Parseable

class Extension(Sendable,Parseable):
    packet_id = 20

    def __init__(self,extension_id,message,rest_data=b''):
        self.extension_id = extension_id
        self.message = message
        self.rest_data = rest_data
    
    def compile_payload(self):
        self.payload = struct.pack(">B",self.extension_id)+Encoder.bencode(self.message)
    
    @classmethod
    def parse(cls, data):
        extension_id = data[0]
        message,rest_data = Decoder.decode_bencode(data[1:],include_rest_data=True)
        return Extension(extension_id, message,rest_data)
