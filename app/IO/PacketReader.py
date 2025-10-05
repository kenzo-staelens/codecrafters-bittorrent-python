import Protocol

from .IO import IO

class PacketReader(IO):
    def work(self):
        while True:
            try:
                ptype, content = Protocol.read_protocol(self.peer.socket,slow=True)
            except ConnectionAbortedError:
                break
            except OSError as e:
                if e.args[0] not in (10054,10038):
                    print("reader: unespected os error",e)
                break
            packet = Protocol.identify_packet(ptype, content)
            packet = Protocol.identify_extension(self.peer.peer_extensions, packet)
            if isinstance(packet, Protocol.Base.RequestsSocket):
                packet.use_socket(self.peer.socket)
            if isinstance(packet, Protocol.Base.Processable):
                packet.process(self.peer)
                continue
            self.packetQueue.put(packet)
    
    def peek(self):
        with self.packetQueue.mutex:
            return self.packetQueue.queue[0]
    
    def get(self):
        return self.packetQueue.get()
    
    def expect(self,packetType):
        while True:
            if (not self.packetQueue.empty()) and type(self.packetQueue.queue[0])==packetType:
                return self.packetQueue.get()

    def expect_any(self, packetTypes):
        while True:
            if (not self.packetQueue.empty()) and type(self.packetQueue.queue[0]) in packetTypes:
                return self.packetQueue.get()