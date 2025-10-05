# https://stackoverflow.com/questions/59730071/getting-peers-quickly-by-announcing-to-the-dht-frequently

import time

MINUTES_15 = 60*15 #seconds = 15 minutes
SLEEP_SECONDS = 5 #seconds

class AsyncDHTProxy:
    def __init__(self,dhtnode,*args,**kwargs):
        self.stopped = False
        self.dhtnode = dhtnode
        self.interval_end = 0
    
    def work(self,infohash, peer_id, info=None, found_queue = None,status=None):
        while not self.stopped:
            if time.time()>=self.interval_end:
                returned_peers = self.get_peers(infohash, peer_id)
                for peer in returned_peers:
                    found_queue.put(peer)
                self.interval_end = time.time() + MINUTES_15 #check every 15 minutes
        time.sleep(SLEEP_SECONDS)
    
    def get_peers(self, infohash, peer_id):
        return self.dhtnode.get_peers(infohash)