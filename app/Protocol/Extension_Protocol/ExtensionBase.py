from bt_bencode.Encoder import Encoder
import struct

def static_init(cls):
    if getattr(cls, "__static_init__", None):
        cls.__static_init__()
    return cls

class ExtensionClassBase:
    def __new__(cls, extension_packet):
        instance = cls.identify(extension_packet)
        instance.name = cls.name
        return instance
    
    @classmethod
    def identify(cls,extension_packet):
        raise NotImplementedError('base class cannot identify packets')
        # packet_type = cls.type_mappings[extension_packet.message['msg_type']]
        # packet_type.parse(extension_packet.message)
    
    @classmethod
    def __static_init__(cls):
        message_classes = [x for x in cls.__dict__.values()  if isinstance(x,type)]
        for message_class in message_classes:
            message_class.name = cls.name

class ExtensionBase:
    packet_id = 20
    
    def compile_message(self):
        raise NotImplementedError('cannot compile base')
    
    def compile_payload(self,extension_dict):
        if self.name == 'handshake':
            extension_id = 0
        else:
            extension_id = extension_dict['m'][self.name]
        self.payload = struct.pack(">B",extension_id) + Encoder.bencode(self.compile_message())
