from Protocol.Base import Parseable, Processable

class Have(Processable, Parseable):
    packet_id = 4
    
    def __init__(self,index):
        self.index = index
    
    @classmethod
    def parse(self, data):
        return Have(data)
    
    def process(self,peer):
        pass
