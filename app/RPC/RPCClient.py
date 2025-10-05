import socket
import json
SIZE = 1024

class RPCClient:
    def __init__(self, host:str='localhost', port:int=8081) -> None:
        self.__sock = None
        self.__address = (host, port)
    
    def connect(self):
        try:
            self.__sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__sock.connect(self.__address)
        except EOFError as e:
            print(e)
            raise Exception('Client was not able to connect.')
    
    def disconnect(self):
        try:
            self.__sock.close()
        except:
            pass
    
    def __getattr__(self, __name: str):
        def excecute(*args, **kwargs):
            self.__sock.sendall(json.dumps((__name, args, kwargs)).encode())

            response = json.loads(self.__sock.recv(SIZE).decode())
   
            return response
        
        return excecute

if __name__ == "__main__":
    client = RPCClient()
    client.connect()
    file = "../sample.torrent"
    # magnet_uri = "magnet:?xt=urn:btih:71316E838C6C393AFF9AD51A2C86D54793C2A7B7&dn=Lovers+in+a+Dangerotime+v1.4.5&tr=http%3A%2F%2Fp4p.arenabg.com%3A1337%2Fannounce"
    # magnet_uri = "magnet:?xt=urn:btih:BA2C4016E429DF170F9DD0F02E13D21D45F4EF68&dn=Nodebuster&tr=http%3A%2F%2Fp4p.arenabg.com%3A1337%2Fannounce&tr=udp%3A%2F%2F47.ip-51-68-199.eu%3A6969%2Fannounce&tr=udp%3A%2F%2F9.rarbg.me%3A2780%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2710%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2730%2Fannounce&tr=udp%3A%2F%2F9.rarbg.to%3A2920%2Fannounce&tr=udp%3A%2F%2Fopen.stealth.si%3A80%2Fannounce&tr=udp%3A%2F%2Fopentracker.i2p.rocks%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.coppersurfer.tk%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.cyberia.is%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.dler.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.internetwarriors.net%3A1337%2Fannounce&tr=udp%3A%2F%2Ftracker.leechers-paradise.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.openbittorrent.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&tr=udp%3A%2F%2Ftracker.pirateparty.gr%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.tiny-vps.com%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.torrent.eu.org%3A451%2Fannounce"
    magnet_uri = "magnet:?xt=urn:bith:BA2C4016E429DF170F9DD0F02E13D21D45F4EF68"
    # print(client.download_file(file))
    print(client.download_magnet(magnet_uri))