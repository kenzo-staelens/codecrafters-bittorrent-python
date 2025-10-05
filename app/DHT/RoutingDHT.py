import struct
import time
from threading import Thread

from .KRPC_Server import KRPC_Server
from .RoutingTable import RoutingTableNode, Node
from .InfoTable import InfoTable, TokenTracker

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

class RoutingDHT:
    initnodes = [
        Node(int("82b4c2f1bbe9ebb3a6db3c870c3e99245e0d1c49",16),("192.168.1.40",37983)),
        Node(int("ba6d6719a03bed22e982ce5e191d83cbfee80237",16),("198.98.61.185",51413))
    ]
    stale_sample = 2 # at most loses 5 seconds
    maintenance_interval = 10 #10 seconds
    
    def __init__(self,host,port,_id):
        self._server = KRPC_Server(host,port)
        self._routing = RoutingTableNode(_id)
        # self._routing.add_node(self.initnodes[0])
        self._routing.add_node(self.initnodes[1])
        self.infotable = InfoTable()
        self._id = _id
        self.tokens = TokenTracker()
    
    def start(self):
        self._server.start()
        self._thread = Thread(target=self.work)
        self._thread.setDaemon(True)
        self._thread.start()
    
    def serialize(self):
        nodes = self._routing.all_nodes()
        packed = self._id + GetPeersResponse.compact_nodes(nodes)
        return packed
    
    def deserialize(self,serialized):
        self._id = serialized[:20]
        nodes = [Node(*n) for n in GetPeersResponse.uncompact_nodes(serialized[20:])]
        for node in nodes:
            self._routing.add_node(node)
        return nodes
    
    def work(self):
        last_maintenance = time.time()
        while True:
            if not self._server.queries.empty():
                packet, addr = self._server.queries.get()
                if packet.node_id == self._id:
                    continue
                node = Node(packet.node_id,addr)
                self.respond_to_query(packet,node)
            else:
                if time.time()-last_maintenance<self.maintenance_interval:
                    continue
                #maintenance
                last_maintenance = time.time()
                self.tokens.cleanup()
                nodes = self._routing.find_stale(N=self.stale_sample)
                for node in nodes:
                    r = self._server.ping(self._id, node)
                    if r is not None:
                        self._routing.add_node(node) # updates node stale time
                    else:
                        self._routing.bad(node._id)
    
    def add_nodes(self,nodes):
        for node in response.nodes:
            self._routing.add_node(node)
    
    def respond_to_query(self, query,node):
        if isinstance(query, Ping):
            self._server.respond_ping(self._id,query, node)
        if isinstance(query, FindNode):
            nodes = self._routing.find_closest(query.target_id,N=8)
            self._server.respond_find_node(self._id, nodes, packet, node)
        if isinstance(query, GetPeers):
            nodes = self._routing.find_closest(query.target_id,N=8)
            nodes = nodes if len(nodes)>0 else None
            values = self.infotable.get(target)
            token = self.tokens.generate_token(node.address)
            self._server.respond_get_peers(self._id, nodes, values, token, packet, node)
        if isinstance(query, Announce):
            if not self.tokens.verify_token(packet.token):
                self._server.respond_error(self, 203,'bad token')
                return #send an error here
            if packet.implied_port==0:
                node.address = (node.address[0],query.port)
            self.infotable.add(packet.info_hash, node)
            self._server.respond_announce_peer(self._id,query, node)
            self.ping(node) #to possibly register in routing table
    
    def recursive_request(self, target, func, max_attempts=20,resultkey=None):
        temp_routing = RoutingTableNode(target) #routing table centered on target
        temp_routing.add_node(Node(int("ba6d6719a03bed22e982ce5e191d83cbfee80237",16),("198.98.61.185",51413)))
        attempts = 0
        while attempts < max_attempts:
            attempts +=1
            for node in temp_routing.find_closest(target):
                try:
                    response = func(self._id,target,node)
                    if response is not None:
                        self._routing.add_nodes([Node(*n) for n in response.nodes])
                        temp_routing.add_nodes([Node(*n) for n in response.nodes])
                    if resultkey is not None and hasattr(response, resultkey) and getattr(response, resultkey) is not None:
                        return getattr(response, resultkey)
                except (TimeoutError, ConnectionResetError):
                    self.infotable.remove(node._id)
                    self._routing.bad(node._id)
                    temp_routing.bad(node._id)
                except Exception as e:
                    import traceback
                    print(traceback.format_exc())
                    pass #this is ok
        return []
    
    def ping(self,node):
        response = self._server.ping(self._id, node)
        if response is not None:
            self._routing.add_node(node)
    
    def announce(self, infohash, port, token,node):
        response = self._server.announce(self._id, infohash, port, token,nodee)
        if response is not None:
            self._routing.add_node(node)
        
    def find_node(self, target):
        response = self.recursive_request(target, self._server.find_node)
        return response
    
    def get_peers(self, infohash):
        response = self.recursive_request(infohash, self._server.get_peers,resultkey='values')
        return response
