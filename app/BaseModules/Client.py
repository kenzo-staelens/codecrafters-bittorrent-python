import functools
import hashlib
import os
from threading import Thread
from queue import Queue

from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

from .Torrent import Torrent
from .Magnet import Magnet
from DHT import RoutingDHT

from Logging import register_logger
logger = register_logger(__name__)

# from RPC import BitTorrentRpcServer

class Client:#(BitTorrentRpcServer):
    def __init__(self):
        super().__init__()
        self.peer_id = bytes.fromhex("361a64f0d2198c9f7545dbc0f2fa03e296f32b7d")
        self.torrents = {}
        self.DHT = RoutingDHT("0.0.0.0",6881,self.peer_id)
        # self.registerMethod(self.download_file)
        # self.registerMethod(self.download_magnet)
        # self.registerMethod(self.read_torrent)
    
    def read_torrent(self, torrent_filename):
        """
        extracts most relevant information from a torrent file
        does not work for torrents downloaded from peers
        """
        with open(torrent_filename,"rb") as f:
            encoded_data = f.read()
        decoded = Decoder.decode_bencode(encoded_data)
        infohash = hashlib.sha1(Encoder.bencode(decoded['info'])).digest()
        announce = decoded['announce'] if 'announce' in decoded else None
        return infohash, announce, decoded['info']

    def save_torrent_info(self,info,infohash):
        """
        saves info dictionary downloaded from peers (see also find_info_for)
        """
        logger.info(f"writing torrent file for {infohash=}")
        if info is None:
            return
        with open(f"saved/torrents/{infohash.hex()}.torrent","wb") as f:
            f.write(info)
    
    def find_info_for(self, torrent):
        """
        this function helps a torrent find the info dictionary
        - returns if info already exists
        - tries to open a downloaded torrent file to continue download
        - downloads the torrent from peers
        """
        if torrent.info is not None:
            if not os.path.isfile(f"saved/torrents/{torrent.infohash.hex()}.torrent"):
                self.save_torrent_info(torrent.info_bytes, torrent.infohash)
            return
        try:
            with open(f"saved/torrents/{torrent.infohash.hex()}.torrent","rb") as f:
                info = Decoder.decode_bencode(f.read())
                torrent.info = info['info']
        except Exception as e:
            logger.info(f"downloading torrent file (infohash={torrent.infohash.hex()}) from peer")
            torrent.find_info()
            self.save_torrent_info(torrent.info_bytes,torrent.infohash)
    
    def persistence_callback(self,piece_index, piece, infohash):
        """
        callback function to save a downloaded piece to disk
        """
        with open(f"saved/pieces/{infohash.hex()}.{piece_index}.piece","wb") as f:
            f.write(piece)
    
    def completed_callback(self,torrent,name,infohash,num_pieces):
        """
        callback function for torrents that completed a download
        merges all pieces into a single file
        """
        if torrent.status.downloaded_pieces != num_pieces:
            return #should retry torrent
        logger.info(f"stitching torrent for {infohash=} {name=}")
        try:
            with open(f"saved/downloads/{name}","wb") as download:
                for i in range(num_pieces):
                    with open(f"saved/pieces/{infohash}.{i}.piece","rb") as piece:
                        download.write(piece.read())
            logger.info(f"completed downloading {name}")
        except Exception as e:
            logger.error(f"error while stitching torrent for {name=}: {e}")
            os.remove(f"saved/downloads/{name}")
    
    def download_file(self, torrent_filename):
        """
        entrypoint to start download using a torrent file
        - calls start download
        """
        infohash, tracker, info = self.read_torrent(torrent_filename)
        logger.info(f"downloading torrent from file source infohash={infohash.hex()}")
        t = Thread(target=self.start_download,args=(infohash, tracker, info))
        t.setDaemon(True)
        t.start()
        return f"started torrent {infohash.hex()}"
    
    def download_magnet(self, magnet_link):
        """
        entrypoint to start download using a magnet link
        - calls start download
        """
        magnet = Magnet(magnet_link)
        logger.info(f"downloading torrent from magnet source {magnet.xt=}")
        t = Thread(target=self.start_download,args=(magnet.xt, magnet.tr))
        t.setDaemon(True)
        t.start()
        return f"started torrent infohash={magnet.xt.hex()}"
    
    def start_download(self, infohash, trackers, info=None):
        """
        main downloader function
        - creates torrent object
        - finds peers for the torrent
        - finds info either locally, already supplied to torrent or via other peers
        - downloads the torrent using callbacks to handle IO
        """
        torrent = Torrent(infohash, self.peer_id, info)
        self.torrents[infohash.hex()] = torrent
        torrent.build_tracker(trackers,self.DHT)
        if info is None:
            self.find_info_for(torrent)
        torrent.download(
            # multitracker.peer_queue,
            self.persistence_callback,
            self.completed_callback
        )
    
    def __enter__(self):
        try:
            with open("saved/clientinfo/dht.dat","rb") as f:
                self.DHT.deserialize(f.read())
        except:
            pass
        self.DHT.start()
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        serialized = self.DHT.serialize()
        with open("saved/clientinfo/dht.dat","wb") as f:
            f.write(serialized)
