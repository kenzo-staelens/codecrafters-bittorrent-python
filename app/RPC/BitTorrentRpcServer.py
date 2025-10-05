import socket
import json
from threading import Thread

SIZE = 1024

class BitTorrentRpcServer:
    def __init__(self, host:str='0.0.0.0', port:int=8081) -> None:
        self.host = host
        self.port = port
        self.address = (host, port)
        self._methods = {}
        self.registerMethod(self.stop)
    
    def registerMethod(self, function) -> None:
        try:
            self._methods.update({function.__name__ : function})
        except:
            raise Exception('A non function object has been passed into RPCServer.registerMethod(self, function)')

    def __handle__(self, client:socket.socket, address:tuple) -> None:
        print(f'Managing requests from {address}.')
        while True:
            try:
                recv = client.recv(4*SIZE).decode()
                functionName, args, kwargs = json.loads(recv)
            except Exception as e:
                print(f'! Client {address} disconnected.')
                break
            # Showing request Type
            # print(f'> {address} : {functionName}({args})')
            print(f'> {address} : {functionName}')

            try:
                response = self._methods[functionName](*args, **kwargs)
            except Exception as e:
                # Send back exeption if function called by client is not registred 
                client.sendall(json.dumps(str(e)).encode())
            else:
                client.sendall(json.dumps(response).encode())

        print(f'Completed requests from {address}.')
        client.close()
    
    def run(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
            sock.bind(self.address)
            sock.listen()

            print(f'+ Server {self.address} running')
            while True:
                try:
                    client, address = sock.accept()

                    Thread(target=self.__handle__, args=[client, address]).start()

                except KeyboardInterrupt:
                    print(f'- Server {self.address} interrupted')
                    break
    
    def stop(self)->None:
        import sys
        sys.exit()