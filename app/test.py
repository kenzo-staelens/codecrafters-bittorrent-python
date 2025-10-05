from DHT.RoutingDHT import RoutingDHT as DHT
import hashlib

import time
dht = DHT(host='0.0.0.0',port=54767, _id=hashlib.sha1("81.244.175.245".encode()).digest())
dht.start()
peers = dht.get_peers(bytes.fromhex("B737ABCE760318F78B5FF369C15DD731397C183D"))
all_nodes = dht._routing.all_nodes()
s=dht.serialize()
d = dht.deserialize(s)
print(peers)
while True:
    time.sleep(1)