import struct
from Protocol.Base import Sendable

import threading

class Request(Sendable):
    packet_id = 6
    BLOCK_SIZE = 1024*16
    
    def __init__(self,piece_index, chunk_index, piece_length, total_length):
        self.piece_index = piece_index
        self.piece_length = piece_length
        self.total_length = total_length
        self.begin = self.BLOCK_SIZE*chunk_index
        
        self.Continue = True
        self.compile_payload() #because it checks if more need to be sent
        self.compiled = True
    
    def truncate_piece(self):
        piece_length = self.piece_length
        offset = (self.piece_index*self.piece_length)
        if self.total_length-offset<piece_length:
            piece_length = self.total_length-offset
        return piece_length
    
    def truncate_piece_chunk(self,piece_length):
        chunk_size = self.BLOCK_SIZE
        if (piece_length - self.begin) < self.BLOCK_SIZE:
            chunk_size = piece_length - self.begin
        return chunk_size
    
    def compile_payload(self):
        piece_length = self.truncate_piece()
        content_size = self.truncate_piece_chunk(piece_length)
        self.payload = struct.pack(">I",self.piece_index) + struct.pack(">I",self.begin) + struct.pack(">I",content_size)
        if content_size != self.BLOCK_SIZE or (self.begin + content_size==self.piece_length):
            self.Continue = False