import math
from IO import PacketReader, PacketWriter
import Protocol
import socket
import hashlib

from Logging import register_logger
logger = register_logger(__name__)


class Peer:
    def __init__(self, address, peer_id):
        self.packetReader = PacketReader(self)
        self.packetWriter = PacketWriter(self)
        self.address = address
        
        self.peer_id = peer_id
        self.reserved = bytearray(8)
        self.reserved[5]|=0x10
        self.available_extensions = {'ut_metadata'}
        self.extensions = Protocol.ExtensionDict({
            'm':{
                    'ut_metadata':1
                }
            })
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.peer_extensions = None
        self.peer_reserved = None
        self.choked = False
    
    def handshake(self, infohash):
        self.socket.connect(self.address)
        
        Protocol.Handshake(bytes(self.reserved),infohash, self.peer_id).send(self.socket)
        try:
            handshake = Protocol.Handshake.read_packet(self.socket)
        except IndexError: #socket was closed
            return
        except Exception as e:
            logger.error(f"error occured while handshaking a peer {type(e)}:{e}")
            self.close()
            return
        self.peer_reserved = bytearray(handshake.reserved)
        self.packetReader.start()
        self.packetWriter.start()
        packet = self.packetReader.expect_any([Protocol.Bitfield,Protocol.ExtendedHandshake])
        if type(packet)==Protocol.ExtendedHandshake:
            #because of course some clients switch the order around
            self.peer_extensions = Protocol.ExtensionDict(packet.handshake_dict)
            self.match_extension_dict()
            self.packetReader.expect(Protocol.Bitfield)
            self.extended_handshake(True)
            return
        #note process bitfield payload high bits mean available
        if self.peer_reserved[5]&self.reserved[5]&0x10==0x10:
            self.extended_handshake()

    def extended_handshake(self,skip_expect = False):
        if not skip_expect:
            ext_handshake = self.packetReader.expect(Protocol.ExtendedHandshake)
            self.peer_extensions = Protocol.ExtensionDict(ext_handshake.handshake_dict)
            self.match_extension_dict()
        self.packetWriter.add(Protocol.Interested())
        self.packetWriter.add(Protocol.ExtendedHandshake(self.extensions.source_dict))
    
    def match_extension_dict(self):
        m = {x[0]:x[1] for x in self.peer_extensions.source_dict['m'].items() if x[0] in self.available_extensions}
        self.extensions = Protocol.ExtensionDict({'m':m})
        
    def download_metadata(self,metadata_size, infohash):
        if metadata_size ==0:
            return b''
        pieces = int(math.ceil(metadata_size/(16*1024)))
        for i in range(pieces):
            self.packetWriter.add(Protocol.UT_Metadata.Request(i))
        piece_data = {}
        for i in range(pieces):
            piece = self.packetReader.expect(Protocol.UT_Metadata.Data)
            piece_data[piece.piece]=piece.data
        info = self.join_piece(piece_data)
        self.verify_hash(info, infohash)
        return info
    
    def join_piece(self,chunks):
        full_content = b''
        keys = list(chunks.keys())
        keys.sort()
        for key in keys:
            full_content += chunks[key]
        return full_content
    
    def verify_hash(self, content, content_hash):
        if hashlib.sha1(content).digest()!=content_hash:
            self.close()
            raise ValueError("invalid hash")
    
    def request_piece(self,piece_idx, piece_length, total_length):
        chunks = dict()
        chunk_index=0 #double duty indexer, counter
        Continue = True
        while Continue:
            req = Protocol.Request(piece_idx,chunk_index,piece_length, total_length)
            self.packetWriter.add(req)
            Continue = req.Continue
            chunk_index+=1
        while len(chunks)<chunk_index:
            piece = self.packetReader.expect(Protocol.Piece)
            chunks[piece.begin]=piece.content
        return chunks

    def download_piece(self,piece_hash, piece_length, total_length, piece_idx):
        self.packetWriter.add(Protocol.Interested())
        chunks = self.request_piece(piece_idx, piece_length, total_length)
        full_content = self.join_piece(chunks)
        self.verify_hash(full_content, piece_hash)
        return full_content
    
    # def is_alive(self,infohash,live_queue=None):
        # try:
            # self.socket.connect(self.address)
            # self.socket.settimeout(2)
            # Protocol.Handshake(bytes(8),infohash, self.peer_id).send(self.socket)
            # handshake = Protocol.Handshake.read_packet(self.socket)
            # if live_queue is not None:
                # live_queue.put(self)
            # return True
        # except Exception as e:
            # print(type(e),e)
            # return False
        # finally:
            # self.socket.close()
    
    def close(self):
        self.socket.close()
