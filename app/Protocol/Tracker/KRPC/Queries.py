from .KRPC_Base import Query, base_query

class Ping(Query):
    name = "ping"
    def __init__(self,node_id):
        self.node_id = node_id
        self.transaction = None
    
    def build(self):
        args={'id':self.node_id}
        packet = base_query(self,args)
        return packet
    
    @classmethod
    def parse(cls, data):
        return Ping(data['a']['id'])

class FindNode(Query):
    name = "find_node"
    def __init__(self,node_id,target_id):
        self.node_id = node_id
        self.target_id = target_id
        self.transaction = None
    
    def build(self):
        args = {'id':self.node_id,'target':self.target_id}
        packet = base_query(self,args)
        return packet
    
    @classmethod
    def parse(cls,data):
        return FindNode(
            data['a']['id'],
            data['a']['target']
        )

class GetPeers(Query):
    name = "get_peers"
    def __init__(self,node_id,info_hash):
        self.node_id = node_id
        self.info_hash = info_hash
        self.transaction = None
    
    def build(self):
        args = {'id':self.node_id,'info_hash':self.info_hash}
        packet = base_query(self,args)
        return packet
    
    @classmethod
    def parse(cls,data):
        return GetPeers(
            data['a']['id'],
            data['a']['info_hash']
        )

class AnnouncePeer(Query):
    name = "announce_peer"
    def __init__(self,node_id,info_hash,port,token):
        self.node_id = node_id
        self.info_hash = info_hash
        self.implied_port = 0
        self.port = port
        self.token = token
        self.transaction = None
    
    def build(self):
        args = {'id':self.node_id,'info_hash':self.info_hash,'port':self.port,'token':self.token}
        packet = base_query(self,args)
        return packet
    
    @classmethod
    def parse(cls,data):
        a = AnnouncePeer(
            data['a']['id'],
            data['a']['info_hash'],
            data['a']['port'],
            data['a']['token']
        )
        if 'implied_port' in data['a']:
            self.implied_port = data['a']['implied_port']

def parse_query(data):
    match data['q']:
        case 'ping':
            return Ping.parse(data)
        case 'find_node':
            return FindNode.parse(data)
        case 'get_peers':
            return GetPeers.parse(data)
        case 'announce_peer':
            return AnnouncePeer.parse(data)
        case _:
            return None