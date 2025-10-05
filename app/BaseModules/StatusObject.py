import glob

from .Bitfield import Bitfield
from threading import Lock

class StatusObject:
    def __init__(self, info, infohash):
        self.infohash = infohash
        self.completed = False
        
        self.num_pieces = 0
        self.pieces_bitfield = Bitfield(self.num_pieces)
        self.downloaded_pieces = 0

        self.concurrency_lock = Lock()
        self.downloaded_bytes = 0
    
    def clear(self):
        self.completed = False
        self.num_pieces = 0
        self.pieces_bitfield = Bitfield(self.num_pieces)
        self.downloaded_pieces = 0
    
    def _check_piece_files(self):
        return set([int(x.split('.')[1]) for x in glob.glob(f"saved/pieces/{self.infohash.hex()}.*.piece")])
    
    def update(self,info):
        self.clear()
        if info is None:
            return
        self.num_pieces = int(len(info['pieces'])/20)
        downloaded = list(self._check_piece_files())
        self.downloaded_pieces = len(downloaded)
        self.pieces_bitfield = Bitfield(self.num_pieces)
        for i in downloaded:
            self.pieces_bitfield[i]=True
        if len(downloaded)==self.num_pieces:
            self.completed = True
    
    def increment_download(self,data_length):
        with self.concurrency_lock:
            self.downloaded_pieces+=1
            self.downloaded_bytes += data_length
            if self.downloaded_pieces>=self.num_pieces:
                self.completed=True
    
    def missing(self):
        return self.pieces_bitfield.missing()
    
    def save(self,filepath):
        pass