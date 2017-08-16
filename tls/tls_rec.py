

# TLS Record Type
TlsRec_AppData = 23
TlsRec_Handshake = 22

TlsRec_ClientHello = 1
TlsRec_ServerHello = 2
TlsRec_Certificate = 11
TlsRec_ServerKeyExchange = 12
TlsRec_ClientKeyExchange = 16

class TlsRecord:
        def __init__(self, sock, major=3, minor=3, dbg=None):
            self.dbg = dbg
            self.sock = sock
            self.major = major
            self.minor = minor
        def send(self, msg):
            type = TlsRec_Handshake
            htype = TlsRec_ClientHello
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + chr(len(msg) & 0xff00)  + chr(htype) + msg
            self.sock.sendall(rec)
        def sendMsg(self, msg):
            type=TlsRec_AppData
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + chr(len(msg) & 0xff00) + msg
            self.sock.sendall(rec)
        def recv(self, sz):
            rec = self.sock.recv(sz)
            sz = len(rec)
            if sz > 5 and self.dbg: print str((rec[0],rec[1], rec[2])) + str((ord(rec[3])<<8) + ord(rec[4]) + ord(rec[5]))
            if sz > 6 and self.dbg: print rec[6:]
            return rec[6:]
        def recvMsg(self, sz):
            rec = self.sock.recv(sz)
            sz = len(rec)
            if sz > 5 and self.dbg: print str((rec[0],rec[1], rec[2])) + str((ord(rec[3])<<8) + ord(rec[4]))
            if sz > 6 and self.dbg: print rec[5:]
            return rec[5:]
