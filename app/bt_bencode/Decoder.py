def bytes_to_str(data):
    if isinstance(data, str):
        return data
    if isinstance(data, bytes):
        return data.decode('utf-8')
    raise TypeError(f"Type not serializable: {type(data)}")

def get_0th(bencoded):
    try:
        v0 = chr(bencoded[0])
    except:
        v0 = bencoded[0]
    return v0

class Decoder:
    @classmethod
    def decode_string(cls,bencoded_value):
        try:
            colon_idx = bencoded_value.find(b":")
        except:
            colon_idx = bencoded_value.find(":")
        if colon_idx == -1:
            raise ValueError("Invalid encoded string")
        length = int(bencoded_value[:colon_idx])
        skip = colon_idx + 1
        decoded = bencoded_value[skip:skip+length]
        try:
            decoded = bytes_to_str(decoded)
        except UnicodeDecodeError:
            pass
        remaining = bencoded_value[skip+length:]
        return decoded, remaining
    
    @classmethod
    def decode_integer(cls,bencoded_value):
        try:
            e_idx = bencoded_value.find(b"e")
        except:
            e_idx = bencoded_value.find("e")
        if e_idx == -1:
            raise ValueError("Invalid encoded string")
        decoded = int(bencoded_value[1:e_idx]) # will itcls also error if not parsable
        remaining = bencoded_value[e_idx+1:]
        return decoded, remaining
    
    @classmethod
    def decode_list(cls,bencoded_value):
        bencoded_value = bencoded_value[1:] #strip l
        result = []
        while get_0th(bencoded_value)!="e":
            decoded, bencoded_value = cls.__decode_bencode(bencoded_value)
            result.append(decoded)
        return result, bencoded_value[1:] # strip the e
    
    @classmethod
    def decode_dict(cls,bencoded_value):
        bencoded_value = bencoded_value[1:] #strip d
        result = {}
        while get_0th(bencoded_value)!="e":
            key, bencoded_value = cls.decode_string(bencoded_value)
            value, bencoded_value = cls.__decode_bencode(bencoded_value)
            result[key]=value
        return result, bencoded_value[1:] #strip e
    
    @classmethod
    def __decode_bencode(cls,bencoded_value):
        v0 = get_0th(bencoded_value)
        if v0.isdigit():
            return cls.decode_string(bencoded_value)
        elif v0=="i":
            return cls.decode_integer(bencoded_value)
        elif v0=="l":
            return cls.decode_list(bencoded_value)
        elif v0=="d":
            return cls.decode_dict(bencoded_value)
        else:
            raise NotImplementedError(f"identifier {bencoded_value[0]} not recognized:\n\t{bencoded_value}")
    
    @classmethod
    def decode_bencode(cls,bencoded_value,*,include_rest_data = False):
        #removes trailing empty bencode
        if not include_rest_data:
            return cls.__decode_bencode(bencoded_value)[0]
        else:
            return cls.__decode_bencode(bencoded_value)
