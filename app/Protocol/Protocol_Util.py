from .Base_Protocol import *
from .Extension_Protocol import ExtendedHandshake
from asyncio import IncompleteReadError

lookup_table={
    0: Choke,
    1: Unchoke,
    2: Interested,
    3: Not_Interested,
    4: Have,
    5: Bitfield,
    6: Request,
    7: Piece,
    20: Extension
}

def read_handshake(socket):
    return Handshake.read_packet(socket)

def readexactly(sock, num_bytes):
    buf = bytearray(num_bytes)
    pos = 0
    while pos < num_bytes:
        n = sock.recv_into(memoryview(buf)[pos:])
        if n == 0:
            raise IncompleteReadError(bytes(buf[:pos]), num_bytes)
        pos += n
    return bytes(buf)

def read_protocol(socket,*,slow=False):
    length = 0
    while length==0: #skip keep alive
        length = int.from_bytes(socket.recv(4),"big")
    message_type = socket.recv(1)[0] #see bep_0003
    content = readexactly(socket,length-1)
    return message_type, content

def identify_packet(message_type, packet_content):
    ptype = lookup_table[message_type]
    parsed = ptype.parse(packet_content)
    if type(parsed)==Extension:
        if parsed.extension_id == 0:
            return ExtendedHandshake(parsed.message)
    return parsed

#extension dict is dynamic
def identify_extension(extension_dict, packet):
    if type(packet) != Extension or extension_dict is None:
        return packet #not extension or not identifyable
    if packet.extension_id not in extension_dict.mapping:
        return packet # extension not found
    return extension_dict.mapping[packet.extension_id](packet)