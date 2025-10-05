from .IO import IO
from queue import Empty
import traceback

class PacketWriter(IO):
    def add(self, packet):
        # if keepalive:
            # packet.send(self.peer.socket,self.peer.extensions)
        self.packetQueue.put(packet)
    
    def work(self):
        while True:
            try:
                if self.peer.socket._closed:
                    break
                if self.peer.choked:
                    continue
                packet = self.packetQueue.get_nowait()
                packet.send(self.peer.socket,self.peer.extensions)
            except Empty:
                pass
            except OSError as e:
                if e.args[0]!=10038:
                    print("writer: unespected os error",e)
                break
            except Exception as e:
                print("packetwriter error:", type(e),e)
                print(traceback.format_exc())