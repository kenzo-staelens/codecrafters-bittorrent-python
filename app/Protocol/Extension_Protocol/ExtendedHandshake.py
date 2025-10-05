import struct
from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

from Protocol.Base import Sendable, Parseable
from .ExtensionBase import ExtensionBase

class ExtendedHandshake(ExtensionBase, Sendable,Parseable):
    packet_id = 20
    name = 'handshake'
    def __init__(self,handshake_dict):
        self.handshake_dict = handshake_dict
    
    def compile_message(self):
        # self.payload = struct.pack(">B",self.extended_id)+Encoder.bencode(self.handshake_dict)
        return self.handshake_dict
    
    @classmethod
    def parse(self, data):
        handshake_dict = Decoder.decode_bencode(data[1:])
        return ExtendedHandshake(handshake_dict)