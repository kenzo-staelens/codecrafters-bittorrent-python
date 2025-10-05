from urllib import parse

class Magnet:
    def __init__(self,magnet_string):
        self.data = parse.parse_qs(parse.urlparse(magnet_string).query)
        self.parse_xt()
        self.parse_tr()
    
    def parse_xt(self):
        xt = self.data['xt'][0]#currently don't support multiple
        _, xt_type, xt_hash = xt.split(":")
        self.xt = bytes.fromhex(xt_hash)
    
    def parse_tr(self):
        if 'tr' in self.data:
            self.tr = self.data['tr']
        else:
            self.tr = []
        # self.tr.append('dht://127.0.0.1:1')
