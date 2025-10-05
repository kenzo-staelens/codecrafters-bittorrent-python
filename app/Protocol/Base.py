import struct

class Sendable:
    compiled = False
    def compile_payload(self):
        raise NotImplementedError("cannot compile base Packet")

    def compile_proto(self,extensiondict):
        if not self.compiled:
            if self.packet_id == 20:
                self.compile_payload(extensiondict)
            else:
                self.compile_payload()
            # self.payload
        self.proto = struct.pack(">I",len(self.payload)+1) + struct.pack(">B",self.packet_id) + self.payload
    
    def send(self,socket, extensiondict=None):
        self.compile_proto(extensiondict)
        socket.send(self.proto)

class Parseable:
    @classmethod
    def parse(cls,data):
        raise NotImplementedError("cannot parse base Packet")

class Processable:
    def process(cls,peer):
        raise NotImplementedError("cannot parse base Packet")

class RequestsSocket:
    def use_socket(self, sock):
        raise NotImplementedError

class EmptyPacket(Sendable, Parseable):
    def compile_payload(self):
        self.payload = b''
    
    @classmethod
    def parse(cls,data):
        return cls()