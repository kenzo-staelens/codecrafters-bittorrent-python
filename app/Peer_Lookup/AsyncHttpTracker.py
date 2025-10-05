import time
import requests

from .Base_Tracker import Base_Tracker
from Protocol.Tracker.HTTP import Announce, AnnounceResponse

from Logging import register_logger
logger = register_logger(__name__)


class AsyncHttpTracker(Base_Tracker):
    
    def set_interval(self, interval):
        self.interval_end = time.time()+interval
    
    #could async
    def work(self, infohash, peer_id, info=None, found_queue = None,status=None):
        logger.info("started")
        while True:
            if time.time()>=self.interval_end:
                logger.info(f"getting peers for infohash={infohash.hex()}")
                self.get_peers(infohash, peer_id, info, found_queue,status)
            time.sleep(0.5)
        logger.info("stopped")
    
    def get_peers(self,infohash, peer_id,info=None,found_queue=None,status=None):
        packet = Announce()
        packet.infohash = infohash
        packet.peer_id= peer_id
        if info is not None:
            packet.set_left(info['length'])
        if status is not None:
            packet.downloaded = status.downloaded_bytes
            #packet.left = status.downloaded_pieces*info['piece length']
        response = requests.get(self.url, params=packet.build())
        response = AnnounceResponse(response.content)
        self.set_interval(response.interval)
        logger.info(f"tracker at {self.url} found {len(response.peers)} peers")
        for peer in response.peers:
            found_queue.put(peer)