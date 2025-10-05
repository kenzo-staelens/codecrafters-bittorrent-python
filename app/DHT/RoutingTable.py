import time

class Node:
    stale_time = 900 # 15 minutes
    def __init__(self, _id, address):
        self._id = _id
        self.address = address
        last_updated = 0
    
    @property
    def stale(self):
        return time.time()-self.last_updated>self.stale_time
    
    def __repr__(self):
        return f'Node({hex(self._id)[2:]} {self.address})'
    
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return self._id == other._id and self.address == other.address
        else:
            return False
    
    def __hash__(self):
        return hash((self._id,self.address))

class RoutingTableNode:
    def __init__(self, viewpoint, prefix=0, bits=0, key_length = 160, k=8):
        if isinstance(viewpoint, bytes):
            viewpoint = int.from_bytes(viewpoint)
        self.key_length = key_length
        self.bits = bits
        self.bucket = {}
        self.children = None
        self.viewpoint = viewpoint
        self.prefix = prefix
        self.mask = ((1<<bits)-1)<<(key_length-bits)
        self.last_update = None
        self.cascade = (viewpoint&self.mask == prefix)
        self.k = k
        self.bad_set = set()
    
    def bad(self, node_id):
        self.bad_set.add(node_id)
        self.remove_node(node_id)
    
    def remove_node(self, node_id):
        if not self.is_valid_child(node_id):
            return
        if self.bucket is not None and node_id in self.bucket:
            del self.bucket[node_id]
        elif self.children is not None:
            [node.remove_node(node_id) for node in self.children]
    
    def add_nodes(self,nodes):
        for node in nodes:
            self.add_node(node)
    
    def all_nodes(self):
        result = []
        if self.bucket is None:
            for child in self.children:
                result.extend(child.all_nodes())
            return result
        result.extend(self.bucket.values())
        return result
    
    def find_stale(self,N=None):
        return list(self._find_stale())[:N]
    
    def _find_stale(self):
        # don't outright delete nodes that are old, make them available to ping instead
        result = set()
        if self.bucket is None:
            for child in self.children:
                result |= child._find_stale()
            return result
        now = time.time()
        for node in self.bucket.values():
            if node.stale:
                result.add(node)
        return result
    
    def _update_node(self,node):
        if node._id in self.bucket:
            self.bucket[node._id].last_updated = time.time()
        if not self.cascade and len(self.bucket)>=self.k:
            return
        node.last_updated = time.time()
        self.bucket[node._id] = node
        
    
    def add_node(self, node):
        if node._id in self.bad_set:
            return
        if self.bucket is None:
            self.children[0].add_node(node)
            self.children[1].add_node(node)
            return
        if node._id & self.mask == self.prefix:
            self._update_node(node)
            if len(self.bucket)>self.k:
                self.overflow()
            
    def overflow(self):
        if not self.cascade:
            return
        bitadd = 1<<(self.key_length-self.bits-1)
        self.children = [
            RoutingTableNode(self.viewpoint, self.prefix, self.bits+1, key_length=self.key_length,k=self.k),
            RoutingTableNode(self.viewpoint, self.prefix+bitadd, self.bits+1,key_length=self.key_length,k=self.k)
        ]
        for node in self.bucket.values():
            for child in self.children:
                child.add_node(node)
        self.bucket=None
        self.last_update = None
    
    def find_closest(self,target,N=3):
        if isinstance(target,bytes):
            target = int.from_bytes(target)
        closest = list(node for node in self._find_closest(target, N) if not node.stale)
        closest.sort(key= lambda x: int.bit_count(target^x._id))
        return closest[:N]
    
    def _find_closest(self,target,N=3):
        if self.bucket is None:
            found = set()
            if self.children[0].is_valid_child(target):
                found = self.children[0]._find_closest(target)
                if len(found)>=N:
                    return found
            found |= self.children[1]._find_closest(target)
            return found
        # print(self.bucket.items())
        return set(self.bucket.values())
    
    def is_valid_child(self, child):
        return child&self.mask == self.prefix
    
    def __str__(self):
        return f"{bin(self.prefix)[2:]:0>16}, {bin(self.mask)[2:]:0>16}, {[f'{bin(x)[2:]:0>16}' for x in self.bucket] if self.bucket is not None else []}, children={self.children is not None}"