from bt_bencode.Decoder import Decoder

class AnnounceResponse:
    def __init__(self,encoded):
        self.interval = 0
        self.peers = []
        try:
            self.raw = self.decode(encoded)
        except Exception as e:
            self.raw = encoded
            print(e)
    
    def decode(self, data):
        decoded = Decoder.decode_bencode(data)
        if 'peers' in decoded:
            peers = decoded['peers']
            self.peers = self.decode_compact_peers(peers)
        if 'interval' in decoded:
            self.interval = decoded['interval']
        return decoded
    
    def decode_compact_peers(self,peers):
        # converts raw bytes to ip:port
        decoded = []
        for i in range(0,len(peers),6):
            decoded.append(
                (f"{peers[i+0]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}",peers[i+4]*256+peers[i+5])
            )
        return decoded