import glob

from bt_bencode import Decoder
from bt_bencode import Encoder

from .StatusObject import StatusObject

class Status:
    def __init__(self,filepath):
        self.filepath = filepath
        self.status = {}

    def load(self):
        try:
            f = open(filepath,"rb")
        except FileNotFoundError:
            open(filepath,"w")
            f = open(filepath,"rb")
        with f:
            self.status = Decoder.decode_bencode(f.read())

    def save(self):
        with open(self.filepath,"wb") as f:
            f.write(Encoder.bencode(self.status))
    
    @classmethod
    def check_piece_files(self, infohash):
        return set([int(x.split('.')[1]) for x in glob.glob(f"saved/pieces/{infohash}.*.piece")])
        

    def add(self, torrent):
        pass