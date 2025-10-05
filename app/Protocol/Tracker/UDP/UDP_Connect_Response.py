import struct

class ConnectResponse:
    def __init__(self,data,transaction_id):
        if len(data)<16:
            raise ValueError(f"data too short: {len(data)}")
        self.action, self.transaction_id, self.connection_id = struct.unpack(">I4s8s",data)
        if transaction_id !=self.transaction_id:
            raise ValueError("transaction id mismatch")