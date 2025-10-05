import sys
import hashlib
import requests
import random
import socket

from util import generate_peer_id
from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

pid = generate_peer_id()


def command_decode(arg):
    return Decoder.decode_bencode(arg)[0]

def command_info(arg):
    with open(arg,"rb") as f:
        bencoded_value = f.read()
    decoded = command_decode(bencoded_value)
    infohash = hashlib.sha1(Encoder.bencode(decoded['info'])).digest()
    return decoded, infohash

def decode_peers(peers):
    #converts raw bytes to ip:port
    decoded = []
    for i in range(0,len(peers),6):
        decoded.append(
            f"{peers[i+0]}.{peers[i+1]}.{peers[i+2]}.{peers[i+3]}:{peers[i+4]*256+peers[i+5]}"
        )
    return decoded

import urllib

def command_peers(torrent, infohash):
    # torrent, infohash = command_info(arg)
    tracker = torrent['announce']
    left = torrent['info']['length']
    peer_id = pid
    params = {
        'info_hash': infohash,
        'peer_id':peer_id,
        'port':6881,
        'uploaded':0,
        'downloaded':0,
        'left':str(left),
        # 'left':str(1),
        'compact':1
    }
    response = requests.get(tracker, params=params)
    peers_response = Decoder.decode_bencode(response.content)[0]
    peers_response['peers'] = decode_peers(peers_response['peers'])
    
    return peers_response, peer_id

def command_handshake(infohash, peer_inet):
    # _, infohash = command_info(arg)
    ip, port = peer_inet.split(":")
    proto = b"\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00"+infohash+pid.encode()
    new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new.connect((ip, int(port)))
    new.send(proto)
    proto_name_len = new.recv(1)[0]
    proto_name = new.recv(proto_name_len)
    reserved = new.recv(8)
    _hash = new.recv(20)
    peer = new.recv(20)
    
    return proto_name, reserved, _hash, peer, new

def read_message(_socket):
    length = int.from_bytes(_socket.recv(4),"big")
    message_id = _socket.recv(1)[0]
    content = _socket.recv(length-1)
    return message_id, content

def read_piece(_socket):
    length = int.from_bytes(_socket.recv(4),"big")-1-8 # id, piece index, begin
    message_id = _socket.recv(1)[0]
    index = int.from_bytes(_socket.recv(4),"big")
    begin = int.from_bytes(_socket.recv(4),"big")
    content = b""
    for i in range(length):
        content += _socket.recv(1) #because sockets
    return message_id, content, index, begin

def create_request(piece_idx, offset, piece_length, all_length, block_size=16*1024):
    begin = offset*block_size
    
    piece_bytes = piece_idx.to_bytes(4, "big")
    begin_bytes = begin.to_bytes(4, "big")

    if all_length-(piece_idx*piece_length)<piece_length:
        piece_length = all_length-(piece_idx*piece_length)

    content_size = block_size
    if piece_length-begin<block_size:
        content_size = piece_length-begin
    block_size_bytes = content_size.to_bytes(4, "big")
    content = b"\x06" + piece_bytes + begin_bytes + block_size_bytes
    length = len(content)
    return length.to_bytes(4,"big") + content, content_size, block_size



def download_piece(_socket,piece, piece_length, all_length, outfile, piece_idx):
    #assume just bittorrent protocol
    read_message(_socket) #first bitfield
    _socket.send(b"\x00\x00\x00\x01\x02")
    message_id, _ = read_message(_socket)
    if message_id == 1:
        expect_length = block_size = 0
        i=0
        while expect_length==block_size:
            to_send, expect_length, block_size = create_request(piece_idx,i, piece_length, all_length)
            if expect_length>0:
                _socket.send(to_send)
                i+=1
        _pieces={}
        for j in range(i):
            _id, content, index, begin=read_piece(_socket)
            if index not in _pieces:
                _pieces[index]={}
            _pieces[index][begin]=content
        
        full_content = b""
        for blocks in _pieces.values():
            keys = blocks.keys()
            list(keys).sort()
            for key in keys:
                full_content += blocks[key]
        
        if hashlib.sha1(full_content).digest()!=piece:
            raise ValueError("invalid piece")
        with open(outfile,"wb") as f:
            f.write(full_content)
        _socket.close()

def breakup_pieces(pieces):
    result = []
    for piece in [pieces[i:i+20] for i in range(0,len(pieces),20)]:
        result.append(piece)
    return result

def main():
    command = sys.argv[1]

    if command == "decode":
        arg = sys.argv[2].encode()
        print(command_decode(arg))
        # print(decode_bencode(bencoded_value)[0])
    elif command == "info":
        torrent, infohash = command_info(sys.argv[2])
        info = torrent['info']
        print(f"Tracker URL: {torrent['announce']}")
        print(f"Length: {info['length']}")
        print(f"Hash: {infohash.hex()}")
        print(f"Piece length: {info['piece length']}")
        print("Piece hashes")
        for piece in breakup_pieces(info['pieces']):
            print(piece.hex())
    elif command == "peers":
        torrent, infohash = command_info(sys.argv[2])
        peers_data,_ = command_peers(torrent,infohash)
        for peer in peers_data['peers']:
            print(peer)
    elif command=="handshake":
        _, infohash = command_info(sys.argv[2])
        proto_name, reserved_bytes, _hash, peer_id, _socket = command_handshake(infohash,sys.argv[3])
        print(peer_id.hex())
    elif command=="download_piece":
        outfile = sys.argv[3]
        piece_idx = int(sys.argv[5])
        torrent, infohash = command_info(sys.argv[4])
        pieces = breakup_pieces(torrent['info']['pieces'])
        
        peers,_ = command_peers(torrent,infohash)
        peer = random.choice(peers['peers']) # = sys.argv[3]
        peer = "178.62.85.20:51489"
        
        _,_,_,_, _socket = command_handshake(infohash,peer)
        piece_length = torrent['info']['piece length']
        all_length = torrent['info']['length']
        download_piece(_socket,pieces[piece_idx],piece_length, all_length,outfile, piece_idx)
    elif command == "download":
        outfile = sys.argv[3]
        torrent, infohash = command_info(sys.argv[4])
        pieces = breakup_pieces(torrent['info']['pieces'])
        peers,_ = command_peers(torrent,infohash)
        piece_length = torrent['info']['piece length']
        all_length = torrent['info']['length']
        for idx, piece in enumerate(pieces):
            peer = random.choice(peers['peers']) # = sys.argv[3]
            _,_,_,_, _socket = command_handshake(infohash,peer)
            download_piece(_socket, piece, piece_length,all_length, f"./pieces/{idx}", idx)
        
        with open(outfile,"ab") as f:
            for i in range(len(pieces)):
                with open(f"./pieces/{i}","rb") as p:
                    f.write(p.read())
        print(f"Downloaded {sys.argv[4]} to {outfile}.")
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
