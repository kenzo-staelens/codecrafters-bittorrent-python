import socket
import struct
from .KRPC_Base import Response, Error, base_response

class PingResponse(Response):
    def __init__(self,transaction,node_id):
        self.node_id = node_id
        self.transaction = transaction
    
    def build(self):
        args={'id':self.node_id}
        packet = base_response(self,args)
        return packet
    
    @classmethod
    def parse(cls, data):
        return PingResponse(
            data["t"],
            data["r"]['id']
        )

class FindNodeResponse(Response):
    def __init__(self,transaction,node_id,nodes):
        self.transaction = transaction
        self.node_id = node_id
        self.nodes = nodes
    
    # def __compact_nodes(self):
        # n = len(self.nodes)
        # def helper(nodes):
            # for _node in nodes:
                # ip = socket.inet_aton(_node.address[0])
                # yield _node._id.to_bytes(20, 'big')
                # yield ip
                # yield _node.address[1]
        # return struct.pack(">"+"20sLH"*n,*list(helper(self.nodes)))
    
    def build(self):
        args = {'id':self.node_id,'nodes':self.compact_nodes(self.nodes)}
        packet = base_response(self,args)
        return packet
    
    # @classmethod
    # def __uncompact_nodes(self,nodes):
        # if isinstance(nodes,str):
            # nodes = nodes.encode()
        # n = int(len(nodes)/26)
        # unpacked = struct.unpack(">"+"20s4sH"*n,nodes)
        # return [(
            # int.from_bytes(unpacked[i]),
            # (socket.inet_ntoa(unpacked[i+1]),
            # unpacked[i+2])) for i in range(0, len(unpacked)-1,3)]
    
    @classmethod
    def parse(cls, data):
        return FindNodeResponse(
            data["t"],
            data["r"]['id'],
            cls.uncompact_nodes(data['r']['nodes'])
        )

class GetPeersResponse(Response):
    def __init__(self,transaction,node_id,token, nodes=None, values=None):
        self.transaction = transaction
        self.node_id = node_id
        self.token = token
        self.nodes = nodes
        self.values = values
    
    def build(self):
        args = {'id':self.node_id,'token':self.token}
        if self.nodes is not None:
            args |={'nodes':self.compact_nodes(self.nodes)}
        if self.values is not None:
            args |={'values':self.compact_values(self.values)}
        
        packet = base_response(self, args)
        return packet
    
    @classmethod
    def parse(cls, data):
        try:
            return GetPeersResponse(
                data['t'],
                data['r']['id'],
                data['r']['token'],
                cls.uncompact_nodes(data['r']["nodes"]) if 'nodes' in data['r'] else None,
                cls.uncompact_values(data['r']["values"]) if 'values' in data['r'] else None
            )
        except Exception as e:
            print(e)
            print(data)
            import sys
            sys.exit()

class AnnouncePeerResponse(PingResponse):
    pass

class KRPCError(Error):
    def __init__(self, transaction, errorcode,errormessage):
        self.transaction = transaction
        self.errorcode = errorcode
        self.errormessage = errormessage
    
    def build(self):
        args = [self.errorcode, self.errormessage]
        return base_response(self, args)
    
    @classmethod
    def parse(cls, data):
        return KRPCError(
            data['t']
            *data['e']
        )
