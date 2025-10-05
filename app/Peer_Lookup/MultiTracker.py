from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
import socket
import asyncio

from .UDP_Tracker import UDP_Tracker
from .HTTP_Tracker import HTTP_Tracker
from .DHT_Proxy import DHT_Proxy

lookup = {
    'udp':UDP_Tracker,
    'http':HTTP_Tracker,
    'dht':DHT_Proxy
}

class MultiTracker:
    def __init__(self, trackers,dht):
        self.trackers = []
        for tracker in trackers:
            try:
                tracker_type = self.identify(tracker)
                if tracker_type == DHT_Proxy:
                    t = tracker_type(dht)
                else:
                    t = tracker_type(tracker)
                self.trackers.append(t)
            except socket.gaierror:
                pass
            except Exception as e:
                print("tracker create error:",e,type(e))
        self._executor = ThreadPoolExecutor(10)
        
    def identify(self,url):
        scheme = urlparse(url).scheme
        return lookup[scheme]
    
    def get_peers(self,infohash, peer_id,info=None,**kwargs):
        print("multitracker finding peers")
        asyncio.run(self._target(infohash,peer_id, info))
        result = set()
        for item in self.temp:
            result |= set(item)
        return {'peers':list(result)}
    
    def get_peers_queue(self,infohash, peer_id,info=None,live_queue = None,**kwargs):
        print("multitracker finding peers with queue")
        for tr in self.trackers:
            Thread(target=tr.get_peers_queue,args=(infohash,peer_id,{'info':info},live_queue)).start()
    
    async def _target(self,infohash,peer_id, info):
        #note {'info':info} is a kwarg
        self.temp = await asyncio.gather(
            *[ self.in_thread(tr.get_peers, (infohash, peer_id),{'info':info}) for tr in self.trackers]
        )
    
    async def in_thread(self,func,args,kwargs):
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, lambda: func(*args,**kwargs))