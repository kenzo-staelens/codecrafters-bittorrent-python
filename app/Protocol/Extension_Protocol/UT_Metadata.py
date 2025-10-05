from Protocol.Base import Sendable, Parseable, RequestsSocket
from Protocol.Protocol_Util import readexactly
from .ExtensionBase import ExtensionClassBase, ExtensionBase, static_init

@static_init
class UT_Metadata(ExtensionClassBase):
    name = 'ut_metadata'
    
    @classmethod
    def identify(cls,extension_packet):
        packet_type = cls.type_mappings[extension_packet.message['msg_type']]
        return packet_type.parse(extension_packet)
    
    class Request(ExtensionBase,Sendable):
        message_type = 0
        def __init__(self, piece):
            self.piece = piece
        
        def compile_message(self):
            return {'msg_type': self.message_type, 'piece': self.piece}
            # self.payload = Encoder.bencode(raw_payload)
    
    class Data(ExtensionBase,Parseable):
        message_type = 1
        def __init__(self, piece, total_size,data):
            self.piece = piece
            self.total_size = total_size
            self.data = data
        
        @classmethod
        def parse(cls, packet):
            piece = packet.message['piece']
            total_size = packet.message['total_size']
            data = packet.rest_data
            return UT_Metadata.Data(piece,total_size,data)
    
    class Reject:
        message_type = 2
        def __init__(self, message):
            pass
    
    type_mappings = {
        0:Request,
        1:Data,
        2:Reject
    }