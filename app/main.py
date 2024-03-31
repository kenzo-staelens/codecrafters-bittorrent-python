import json
import sys

# import bencodepy - available if you need it!
# import requests - available if you need it!

# Examples:
#
# - decode_bencode(b"5:hello") -> b"hello"
# - decode_bencode(b"10:hello12345") -> b"hello12345"

def decode_string(bencoded_value):
    colon_idx = bencoded_value.find(b":")
    if colon_idx == -1:
        raise ValueError("Invalid encoded string")
    length = int(bencoded_value[:colon_idx])
    skip = colon_idx + 1
    decoded = bencoded_value[skip:skip+length]
    remaining = bencoded_value[skip+len(decoded):]
    return decoded, remaining

def decode_integer(bencoded_value):
    e_idx = bencoded_value.find(b"e")
    if e_idx == -1:
        raise ValueError("Invalid encoded string")
    decoded = int(bencoded_value[1:e_idx]) # will itself also error if not parsable
    remaining = bencoded_value[e_idx+1:]
    return decoded, remaining

def decode_list(bencoded_value):
    bencoded_value = bencoded_value[1:]
    result = []
    while chr(bencoded_value[0])!="e":
        decoded, bencoded_value = decode_bencode(bencoded_value)
        result.append(decoded)
    return result, bencoded_value[1:] # strip the e

def decode_bencode(bencoded_value):
    if chr(bencoded_value[0]).isdigit():
        return decode_string(bencoded_value)
    elif chr(bencoded_value[0])=="i":
        return decode_integer(bencoded_value)
    elif chr(bencoded_value[0])=="l":
        return decode_list(bencoded_value)
    else:
        print(bencoded_value, bencoded_value[0])
        raise NotImplementedError("Only strings are supported at the moment")

# json.dumps() can't handle bytes, but bencoded "strings" need to be
# bytestrings since they might contain non utf-8 characters.
#
# Let's convert them to strings for printing to the console.
def bytes_to_str(data):
            if isinstance(data, bytes):
                return data.decode()

            raise TypeError(f"Type not serializable: {type(data)}")

def main():
    command = sys.argv[1]

    # You can use print statements as follows for debugging, they'll be visible when running tests.
    # print("Logs from your program will appear here!")

    if command == "decode":
        bencoded_value = sys.argv[2].encode()

        # Uncomment this block to pass the first stage
        print(json.dumps(decode_bencode(bencoded_value)[0], default=bytes_to_str))
    else:
        raise NotImplementedError(f"Unknown command {command}")


if __name__ == "__main__":
    main()
