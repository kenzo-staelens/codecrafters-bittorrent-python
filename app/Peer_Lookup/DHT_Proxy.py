from .Base_Tracker import Base_Tracker
from DHT import DHT

class DHT_Proxy(Base_Tracker):
    def __init__(self,dhtnode):
        self.dhtnode = dhtnode
    
    def get_peers(self, infohash, peer_id, **kwargs):
        return self.dhtnode.get_peers(infohash)
        
    def _get_peers(self,infohash, peer_id,**kwargs):
        return DHT.get_peers_recursive(infohash, peer_id, limit=4)
    
    def _get_peers_queue(self, infohash, peer_id, info=None,live_queue=None):
        if live_queue is None:
            raise ValueError("live queue required")
        peers = self.get_peers(infohash,peer_id,info)
        for peer in peers:
            live_queue.put(peer)