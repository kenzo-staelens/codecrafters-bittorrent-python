from Protocol.Base import EmptyPacket, Processable

class Unchoke(Processable, EmptyPacket):
    packet_id = 1
    
    def process(self,peer):
        peer.choked = False
