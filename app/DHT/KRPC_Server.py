import socket
import time
from threading import Thread, Lock
from queue import Queue

from Protocol.Tracker.KRPC.Queries import (
        Ping,
        FindNode,
        GetPeers,
        AnnouncePeer,
        parse_query
    )
from Protocol.Tracker.KRPC.Responses import (
        PingResponse,
        FindNodeResponse,
        GetPeersResponse,
        AnnouncePeerResponse,
        KRPCError
    )
from Protocol.Tracker.KRPC.KRPC_Base import Query

from bt_bencode.Decoder import Decoder
from bt_bencode.Encoder import Encoder

typemap = {
    Ping:PingResponse,
    FindNode:FindNodeResponse,
    GetPeers:GetPeersResponse,
    AnnouncePeer:AnnouncePeerResponse,
    PingResponse:Ping,
    FindNodeResponse:FindNode,
    GetPeersResponse:GetPeers,
    AnnouncePeerResponse:AnnouncePeer
}

class KRPC_Server:
    timeout = 2.5 #seconds
    delay = 0.1 #seconds
    
    def __init__(self,host,port):
        self.host = host
        self.port = port
        self._sock = None
        self._transactions = {}
        self._responses = {}
        self.__transaction_lock = Lock()
        self.__response_lock = Lock()
        self.queries = Queue()
    
    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.settimeout(0.5)
        self._sock.bind( (self.host,self.port) )
        self._thread = Thread(target=self.work)
        self._thread.daemon = True
        self._thread.start()
    
    def process_response(self, resp):
        with self.__transaction_lock:
            if resp['t'] not in self._transactions:
                return
            rtype = self._transactions[resp['t']]
            del self._transactions[resp['t']]
        packet = rtype.parse(resp)
        with self.__response_lock:
            self._responses[packet.transaction] = packet
    
    def process_error(self, err):
        print(err)
        with self.__transaction_lock:
            del self._transactions[err['t']]
    
    def process_query(self, query,addr):
        q = parse_query(query)
        self.queries.put((q,addr))
    
    def work(self):
        while True:
            try:
                rec,addr = self._sock.recvfrom(4096)
                data = Decoder.decode_bencode(rec)
                if 'r' in data:
                    self.process_response(data)
                elif 'e' in data:
                    self.process_error(data)
                elif 'q' in data:
                    self.process_query(data,addr)
                else:
                    print(data)
                    print("unknown krpc message")
            except TimeoutError:
                pass
            except ConnectionResetError:
                pass #should not pass, is bad node
            except Exception as e:
                import traceback
                print(traceback.format_exc())
    
    def send_message(self, req , node):
        responsetype = typemap[type(req)]
        request = req.build()
        data = Encoder.bencode(request)
        if isinstance(req, Query):
            with self.__transaction_lock:
                self._transactions[req.transaction] = responsetype

        self._sock.sendto(data, node.address)
        return req.transaction
    
    def wait_response(self,transaction_id):
        dt = 0
        while transaction_id not in self._responses:
            if transaction_id not in self._transactions:
                #deleted by encountering error
                return None
            time.sleep(self.delay)
            dt+=self.delay
            if dt>self.timeout:
                with self.__transaction_lock:
                    del self._transactions[transaction_id]
                return None
        with self.__response_lock:
            response = self._responses[transaction_id]
            del self._responses[transaction_id]
        
        return response
    
    def ping(self, _id, node):
        packet = Ping(_id)
        transaction_id = self.send_message(packet,node)
        return self.wait_response(transaction_id)
    
    def announce(self, _id, infohash, port, token, node):
        packet = AnnouncePeer(_id, infohash, port, token)
        transaction_id = self.send_message(packet,node)
        return self.wait_response(transaction_id)
    
    def get_peers(self, _id, infohash,node):
        packet = GetPeers(_id, infohash)
        transaction_id = self.send_message(packet,node)
        
        return self.wait_response(transaction_id)

    def find_node(self, _id, target,node):
        packet = FindNode(_id, target)
        transaction_id = self.send_message(packet,node)
        return self.wait_response(transaction_id)
    
    def respond_ping(self, _id, packet, node):
        response = PingResponse(packet.transaction,_id)
        self.send_mesage(response,node)

    def respond_announce(self, _id, packet, node):
        response = PingResponse(packet.transaction,_id)
        self.send_mesage(response,node)
    
    def respond_get_peers(self,_id, nodes, values,token, packet, node):
        response = GetPeersResponse(packet.transaction,_id,token, nodes, values)
        self.send_mesage(response,node)
    
    def respond_find_node(self,_id, nodes, packet, node):
        response = FindNodeResponse(packet.transaction,_id,nodes)
        self.send_mesage(response,node)
    
    def respond_error(self, error_code, error_message,packet,node):
        response = KRPCError(packet.transaction,error_code, error_message)
        self.send_message(response,node)
