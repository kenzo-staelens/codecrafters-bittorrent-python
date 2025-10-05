from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

from threading import Thread, Lock
from queue import Queue
from .Peer import Peer
from .Status import Status
from .StatusObject import StatusObject

import time
from Peer_Lookup import AsyncMultiTracker

from Logging import register_logger
logger = register_logger(__name__)

class Torrent:
    def __init__(self,infohash,peer_id, info=None):
        self.infohash = infohash
        self.status = None
        # self.peer_id = bytes.fromhex("361a64f0d2198c9f7545dbc0f2fa03e296f32b7d")
        self.peer_id = peer_id
        
        self.tracker = None
        self.persistence_lock = Lock()
        self.piece_queue = Queue()
        self.info = info
    
    @property
    def info_bytes(self):
        if self.info is None:
            return None
        return Encoder.bencode({'info':self.info})
    
    @property
    def info(self):
        return self.__info
    
    @info.setter
    def info(self,value):
        logger.info(f"updating torrent info infohash={self.infohash.hex()}")
        self.__info = value
        if self.status is None:
            self.status = StatusObject(self.__info, self.infohash)
        self.status.update(value)
        logger.info(f"finished updating torrent status infohash={self.infohash.hex()}")
        if value is not None:
            self.collect_piece_hashes()
        logger.info(f"finished collecting piece data with infohash={self.infohash.hex()}")
    
    def build_tracker(self, trackers,dhtNode):
        if not isinstance(trackers,list):
            trackers = [trackers]
        multitracker = AsyncMultiTracker(self.infohash,self.peer_id,self.status)
        for tracker in trackers:
            multitracker.add_tracker(tracker)
        multitracker.add_dht(dhtNode)
        multitracker.start()
        self.tracker = multitracker
    
    def collect_piece_hashes(self):
        completed_pieces = Status.check_piece_files(self.infohash.hex())
        pieces = self.info['pieces']
        with self.piece_queue.mutex:
            self.piece_queue.queue.clear()
        missing = self.status.missing()
        for piece_num,piece in enumerate([pieces[i:i+20] for i in range(0,len(pieces),20)]):
            if piece_num in missing:
                self.piece_queue.put((piece_num,piece))
    
    def find_info(self):
        while not self.tracker.peer_queue.empty():
            try:
                flagged = False
                peer_data = self.tracker.peer_queue.get()
                peer = Peer(peer_data,self.peer_id)
                peer.handshake(self.infohash)
                if peer.peer_extensions is not None and 'ut_metadata' in peer.peer_extensions:
                    #otherwise peer valid but cannot send metadata
                    info = peer.download_metadata(peer.peer_extensions['metadata_size'],self.infohash)
                    if info is not None:
                        info = Decoder.decode_bencode(info)
                        self.info = info
                        break
            except (ConnectionRefusedError,ConnectionResetError,TimeoutError):
                flagged = True #peer not usable, don't continue with it
            finally:
                peer.close()
                if not flagged:
                    peers_queue.put(peer_data) # put peer back as usable
    
    def get_next_piece(self):
        if self.piece_queue.empty():
            return None, None
        return self.piece_queue.get()
    
    def peer_thread(self, peer, callback):
        try:
            peer.handshake(self.infohash)
        except (ConnectionRefusedError, ConnectionResetError, TimeoutError):
            peer.close()
            return
            
        idx, piece_hash = self.get_next_piece()
        while idx is not None:
            logger.info(f"peer {peer.address} downloading piece {idx}/{self.status.num_pieces} for {self.infohash.hex()}")
            try:
                piece = peer.download_piece(
                    piece_hash,
                    self.info['piece length'],
                    self.info['length'],
                    idx
                )
                callback(idx,piece,self.infohash)
                self.status.increment_download(len(piece))
                idx, piece_hash = self.get_next_piece()
            except (ValueError) as e:
                logger.warn(f"valueerror trying to download piece {idx} of {self.infohash.hex()} from peer {peer.address}\n\t{e}")
                if idx is not None and piece_hash is not None:
                    self.piece_queue.put((idx,piece_hash))#reset failed get
                    #don't close
            except (ConnectionRefusedError, ConnectionResetError,TimeoutError):
                if idx is not None and piece_hash is not None:
                    self.piece_queue.put((idx,piece_hash))#reset failed get
                break
        peer.close()
        
    def download(self,persistence_callback,completed_callback):
        threads = []
        while not self.status.completed:
            if self.tracker.peer_queue.empty():
                time.sleep(1)
                continue
            
            peer_data = self.tracker.peer_queue.get()
            logger.info(f"starting peer {peer_data} for {self.infohash.hex()}")
            peer = Peer(peer_data, self.peer_id)
            thread = Thread(target = self.peer_thread,args=(peer,persistence_callback))
            thread.setDaemon(True)
            thread.start()
            threads.append(thread)

        completed_callback(
            self,
            self.info['name'] if 'name' in self.info else self.infohash.hex(),
            self.infohash.hex(),
            self.status.num_pieces
        )
        self.tracker.stop()