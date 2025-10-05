import time
import socket

from .Base_Tracker import Base_Tracker
from Protocol.Tracker.UDP import Connect, ConnectResponse, Announce, AnnounceResponse

from Logging import register_logger
logger = register_logger(__name__)


MINUTE = 60

class AsyncUDPTracker(Base_Tracker):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self.connection_expire = 0
        self.cid = None
        self.stopped = False
    
    def load_connection_id(self):
        if self.connection_expire<time.time():
            self.cid = self.connect()
            self.connection_expire = time.time()+MINUTE
            return self.cid
        else:
            return self.cid
    
    def IO(self,packet, responseClass,trans_id=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        sock.sendto(packet.build(),self.address)
        data=sock.recvfrom(1024)[0]
        if trans_id is not None:
            return responseClass(data,trans_id)
        return responseClass(data)
    
    def connect(self):
        try:
            packet = Connect()
            resp = self.IO(packet, ConnectResponse,packet.transaction_id)
            return resp.connection_id
        except TimeoutError:
            self.stopped = True
            return None
    
    def set_interval(self, interval):
        self.interval_end = time.time()+interval
    
    def get_peers(self, infohash, peer_id, info=None, found_queue=None,status=None):
        logger.info(f"connecting to tracker at {self.url}")
        cid = self.load_connection_id()
        if cid is None:
            logger.info(f"failed to connect to tracker at {self.url}")
            return
        packet = Announce(cid)
        packet.infohash = infohash
        packet.peer_id = peer_id
        if status is not None:
            packet.downloaded = status.downloaded_bytes
            #packet.left = status.downloaded_pieces*info['piece length']
        resp = self.IO(packet, AnnounceResponse, packet.transaction_id)
        self.set_interval(resp.interval)
        logger.info(f"tracker at {self.url} found {len(resp.peers)} peers")
        for peer in resp.peers:
            found_queue.put(peer)
    
    #could async
    def work(self, infohash, peer_id, info=None, found_queue = None,status=None):
        logger.info("started")
        while not self.stopped:
            if time.time()>=self.interval_end:
                logger.info(f"getting peers for {infohash}")
                self.get_peers(infohash, peer_id, info, found_queue,status)
            time.sleep(0.5)
        logger.info("stopped")