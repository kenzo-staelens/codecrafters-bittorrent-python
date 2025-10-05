from pprint import pprint
from random import randbytes, choice
import socket
import string
import struct

from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

peer_id_global = randbytes(20)
visited = set()

class DHT:
    def __init__(self):
        pass
    
    @classmethod
    def generate_root_payload(cls,request,payload):
        return{
                'a': payload,
                'q': request,
                't': 'ab',#generate random 2 chars
                'y': 'q'
            }
            #''.join([random.choice(string.ascii_letters) for _ in range(2)])
    
    @classmethod
    def generic_request(cls,address,payload):
        try:
            query_bencoded = Encoder.bencode(payload)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(5)
            s.sendto(query_bencoded,address)
            data, addr = s.recvfrom(1024)
            response = Decoder.decode_bencode(data)
            return response
        except (ConnectionRefusedError,TimeoutError):
            return None
        except Exception as e:
            return None
        finally:
            s.close()
    
    @classmethod
    def ping(cls, host, port, peer_id):
        payload = {"id":peer_id}
        query = cls.generate_root_payload("ping",payload)
        return cls.generic_request((host,port),query)
        

    @classmethod
    def find_node(cls,host,port,peer_id,target_id):
        payload = {"id" : peer_id, "target" : target_id}
        query = cls.generate_root_payload("find_node",payload)
        return cls.generic_request((host,port),query)
    
    @classmethod
    def get_peers_step(cls,host,port,peer_id,infohash):
        if type(infohash)==str:
            infohash = bytes.fromhex(infohash)
        payload = {"id" : peer_id, "info_hash" : infohash}
        query = cls.generate_root_payload("get_peers",payload)
        response = cls.generic_request((host,port),query)
        if response is None:
            return None, []
        if 'r' not in response:
            return None,[]
        if "values" in response['r']:
            #for those few that somehow can get decoded into a string
            resp = [x.encode() if type(x)==str else x for x in response['r']['values']]
            return True, resp
            # return True, response['r']['values']
        if not 'nodes' in response['r']:
            return None,[]
        ret = []
        for i in range(0, len(response['r']['nodes']), 26):
            s = response['r']['nodes'][i:i+26]
            pid = s[:20]
            ip = socket.inet_ntop(socket.AF_INET, s[-6:][:4])
            port = struct.unpack("!H", s[-2:])[0]
            ret += [(ip, port)]
        return False, ret
    
    @classmethod
    def process_peers(cls,peers):
        ret = []
        for peer in peers:
            ip = socket.inet_ntop(socket.AF_INET, peer[:4])
            port = struct.unpack("!H", peer[-2:])[0]
            ret += [(ip, port)]
        return ret
    
    @classmethod
    def get_peers(cls, host, port, peer_id, infohash):
        #find more if too few... make this function recursive until threshold reached?
        peers = [(host,port)]
        found = False
        while not found:
            peers_temp = []
            # found, peers = DHT.get_peers_step(*peers[0],peer_id, infohash)
            while len(peers_temp) == 0:
                peer = choice(peers)
                peers.remove(peer) # don't take chance on double search
                found, peers_temp = cls.get_peers_step(*peer,peer_id, infohash)
            peers = peers_temp
        return cls.process_peers(peers)
    
    @classmethod
    def __get_peers_recursive(cls,peers_list, peer_id, infohash, *, result=None,limit=8):
        if result is None:
            result = set()
        for peer in peers_list:
            if len(result)>=limit:
                break
            if peer in visited:
                continue
            visited.add(peer)
            found, peers_temp = cls.get_peers_step(*peer, peer_id, infohash)
            if found is None:
                continue
            elif found:
                for processed_peer in cls.process_peers(peers_temp):
                    result.add(processed_peer)
            else:
                result = cls.__get_peers_recursive(peers_temp, peer_id, infohash, result=result,limit=limit)
        return result
    
    @classmethod
    def nearest_peer_lookup(cls, infohash):
        return False, [('221.219.25.219',63219)]
        # return False, [("192.168.1.40",37983)]
        # return False, [("185.21.217.17",60436)]
    
    @classmethod
    def get_peers_recursive(cls, infohash, peer_id,limit=1):
        peer_id = peer_id_global
        _, peer_list = cls.nearest_peer_lookup(infohash)
        peers = cls.__get_peers_recursive(peer_list, peer_id, infohash, limit=limit)
        visited = set()
        return list(peers)
    
    @classmethod
    def announce_peer(cls):
        pass

if __name__=="__main__":
    # host,port = socket.gethostbyname("router.bitcomet.com"), 6881
    # peer_id = randbytes(20)
    peer_id = peer_id_global
    # host, port = "192.168.1.40", 37983
    infohash = bytes.fromhex("954B7FE36E45AA4326A99F93E66AAC0F607D0F4B")
    # peers = DHT.get_peers_recurse([(host, port)], peer_id,infohash,limit=2)
    peers = DHT.get_peers_recursive(peer_id,infohash,limit=2)
    # peers = DHT.get_peers(host, port, peer_id,infohash)
    pprint(peers)