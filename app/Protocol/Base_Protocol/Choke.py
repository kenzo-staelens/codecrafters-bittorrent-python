from Protocol.Base import EmptyPacket, Processable

class Choke(Processable, EmptyPacket):
    packet_id = 0
    
    def process(self,peer):
        peer.choked = True
