class Encoder:
    @classmethod
    def bencode_integer(cls,value):
        return f"i{value}e".encode()
    
    @classmethod
    def bencode_string(cls,value):
        if type(value) == bytes:
            return str(len(value)).encode()+b":"+value
        return f"{len(value)}:{value}".encode()
    
    @classmethod
    def bencode_list(cls,value):
        return b"l"+b"".join([cls.bencode(x) for x in value])+b"e"
    
    @classmethod
    def bencode_dict(cls,value):
        return b"d"+b"".join([cls.bencode_string(k)+cls.bencode(v) for k,v in value.items()])+b"e"
    
    @classmethod
    def bencode(cls,value):
        if type(value)==int:
            return cls.bencode_integer(value)
        elif type(value)==str or type(value)==bytes:
            return cls.bencode_string(value)
        elif type(value)==list:
            return cls.bencode_list(value)
        elif type(value)==dict:
            return cls.bencode_dict(value)
        else:
            raise ValueError(f"non encodable object {type(value)}")
