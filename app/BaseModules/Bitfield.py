class Bitfield:
    def __init__(self,length):
        self.field = [False]*length
        
    @property
    def bits(self):
        bits = 0
        for item in self.field:
            if self.field:
                bits+=1
            bits<<=1
        bits<<=(8-len(self)%8) #padding
        return int.to_bytes(bits)
    
    def clear(self):
        self.field = [False for x in self.field]
    
    def have(self):
        return [i for i in range(len(self.field)) if self.field[i]]
    
    def missing(self):
        return [i for i in range(len(self.field)) if not self.field[i]]
    
    def __getitem__(self, index):
        return self.field[index]
    
    def __setitem__(self, index, value):
        if value not in (0,1,True, False):
            raise ValueError("cannot set non boolean value")
        if value in (0,1):
            value = bool(value)
        self.field[index] = value
    
    
    def __len__(self):
        return len(self.field)
    
    def __repr__(self):
        return f'{self.field=} {self.have()=} {self.missing()=}'