from urllib.parse import urlparse
import socket
from queue import Queue

from .AsyncUDPTracker import AsyncUDPTracker
from .AsyncHttpTracker import AsyncHttpTracker
from .AsyncDHTProxy import AsyncDHTProxy
import Protocol
# from .DHT_Proxy import DHT_Proxy
from Concurrent import KillableThread, HangableThread

from Logging import register_logger
logger = register_logger(__name__)

class AsyncMultiTracker:
    lookup = {
        'udp':AsyncUDPTracker,
        'http':AsyncHttpTracker
    }
    
    def __init__(self,infohash,peer_id,status=None):
        self.started = False
        self.infohash = infohash
        self.peer_id = peer_id
        self.found_queue = Queue()
        self.peer_queue = Queue()
        self.info = None
        self.trackers = []
        self.trackerThreads=[]
        self.liveCheckThread = KillableThread(target=self.livecheck)
        self.torrent_status = status
    
    def set_tracker(self, trackers):
        self.trackers = self.identify_trackers(trackers)
    
    def add_tracker(self, tracker):
        if isinstance(tracker,str):
            trackerobj = self.identify_tracker(tracker)
        else:
            trackerobj = tracker
        if trackerobj is not None:
            self.trackers.append(trackerobj)
    
    def add_dht(self, dhtnode):
        trackerobj = AsyncDHTProxy(dhtnode)
        self.trackers.append(trackerobj)
    
    def set_info(self, info):
        self.info = info
    
    def livecheck(self):
        while True:
            if not self.found_queue.empty():
                HangableThread(
                    target=self.lifecheck_helper,
                    args=(self.found_queue.get(),)
                ).start(5) # dies after 5 seconds
    
    def lifecheck_helper(self, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(address)
            sock.settimeout(2)
            Protocol.Handshake(bytes(8),self.infohash, self.peer_id).send(sock)
            handshake = Protocol.Handshake.read_packet(sock)
            self.peer_queue.put(address)
        except (ConnectionRefusedError,IndexError):
            pass
        except Exception as e:
            logger.error(f"an error occured during operation of livecheck {type(e)} {e}")
        finally:
            sock.close()
    
    def start(self):
        logger.info(f"attempted to start multitracker with infohash {self.infohash.hex()}")
        if self.started:
            logger.warn(f"attempted to start already running multitracker with infohash {self.infohash.hex()}")
            raise RuntimeError("multitracker already started")
        self.started = True
        for tracker in self.trackers:
            t = KillableThread(
                #convert to work loop later
                target=tracker.work,
                args=(
                    # tracker,
                    self.infohash,
                    self.peer_id,
                ),
                kwargs={
                    'info':self.info,
                    'found_queue':self.found_queue,
                    'status':self.torrent_status
                }
            )
            self.trackerThreads.append(t)
            # t.setDaemon(True)
            t.start()
        self.liveCheckThread.start()
    
    def stop(self):
        logger.info(f"stopping multitracker with infohash {self.infohash.hex()}")
        [t.kill() for t in self.trackerThreads]
        [t.join() for t in self.trackerThreads]
        self.liveCheckThread.kill()
        self.liveCheckThread.join()
        self.started = False
    
    @classmethod
    def identify_trackers(cls,trackers):
        tracker_list = []
        for tracker in trackers:
            t = cls.identify_tracker(tracker)
            if t is None:
                continue
            tracker_list.append(t)
        return tracker_list
    
    @classmethod
    def identify_tracker(cls,tracker):
        try:
            tracker_type = cls.identify(tracker)
            t = tracker_type(tracker)
            return t
        except socket.gaierror:
            return None
        except Exception as e:
            logger.error(f"an error occured while creating a tracker object {type(e)}: {e}")
            return None
    
    @classmethod
    def identify(cls,url):
        scheme = urlparse(url).scheme
        return cls.lookup[scheme]
