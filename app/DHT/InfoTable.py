from threading import Lock
import time
import os

class InfoTable:
    def __init__(self):
        self.table = {}
    
    def add(self, infohash,node):
        if not infohash in self.table:
            self.table[infohash] = set()
        self.table[infohash].add(node)
    
    def get(self, infohash):
        if infohash in self.table:
            return self.table[infohash]
        return None
    
    def remove(self, node):
        for key in self.table:
            if node in table[key]:
                table[key].remove(node)

class TokenTracker:
    discard_after = 600 #seconds = 10 minutes
    update_secret_after = 300 # 5 minutes
    secret_lenth = 24
    def __init__(self):
        self.active_tokens = {}
        self.secret = (None, 0)
        self.token_lock = Lock()
    
    def cleanup(self):
        discard_all_before = time.time() - self.discard_after
        for token in self.active_tokens:
            _, t = self.active_tokens[token]
            if t<=discard_all_before:
                with self.token_lock:
                    del self.active_tokens[token]
    
    def verify_token(self,token, address):
        self.cleanup() #force cleanup of tokens in case the token expired since last cleanup
        return token in self.active_tokens and self.active_tokens[token][0] == address
    
    def update_secret(self,now):
        if now-self.secret[1]>self.update_secret_after:
            self.secret = (os.urandom(self.secret_lenth), now)
    
    def generate_token(self,address):
        now = time.time()
        self.update_secret(now)
        address_hash = hash(address).to_bytes(8,'big',signed=True)
        token = hashlib.sha1(address_hash+self.secret[0])
        with self.token_lock:
            self.active_tokens[token] = (address,now)