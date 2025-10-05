from urllib.parse import urlparse
import socket

class Base_Tracker:
    def __init__(self, url):
        self.url = url
        self.address = self.get_host_info()
        self.interval_end = 0
    
    def get_peers(self,infohash, peer_id, **kwargs):
        raise NotImplementedError("base class tracker, can't get peers")
    
    def get_host_info(self):
        parsed = urlparse(self.url)
        host,port = parsed.hostname, parsed.port
        # _, host, port = self.url.split(":")
        ip = socket.gethostbyname(host)
        if port is None:
            port = 6881
        return ip,port