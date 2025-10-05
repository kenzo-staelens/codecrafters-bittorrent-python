import requests

from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

from .Base_Tracker import Base_Tracker

def decode_compact_peers(peers):
    print("serialization called")
    #converts raw bytes to ip:port
    decoded = []
    for i in range(0,len(peers),6):
        decoded.append(
            (f"{peers[i+0]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}",peers[i+4]*256+peers[i+5])
        )
    return decoded

class HTTP_Tracker(Base_Tracker):
    def get_peers(self,infohash,info=None):
        # if tracker available
        if info is None:
            left = 16384
        else:
            left = info['length']
        params = {
            'info_hash': infohash,
            'peer_id': self._id,
            'port':6881,
            'uploaded':0,
            'downloaded':0,
            'left':str(left),
            'compact':1
        }
        response = requests.get(self.url, params=params)
        peers_response = Decoder.decode_bencode(response.content)
        if 'peers' in peers_response:
            peers_response['peers'] = decode_compact_peers(peers_response['peers'])
            return peers_response['peers']
        return []
    
    # def decode_peers(self,peers):
        # # converts raw bytes to ip:port
        # decoded = []
        # for i in range(0,len(peers),6):
            # decoded.append(
                # (f"{peers[i+0]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}",peers[i+4]*256+peers[i+5])
            # )
        # return decoded
    
    def get_peers_queue(self, infohash, peer_id, info=None,live_queue=None):
        if live_queue is None:
            raise ValueError("live queue required")
        peers = self.get_peers(infohash,peer_id,info)
        for peer in peers:
            live_queue.put(peer)