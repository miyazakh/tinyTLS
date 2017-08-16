

# TLS Record Type
TlsRec_AppData = 23
TlsRec_Handshake = 22

TlsRec_ClientHello = 1
TlsRec_ServerHello = 2
TlsRec_Certificate = 11
TlsRec_ServerKeyExchange = 12
TlsRec_ClientKeyExchange = 16

class TlsRecord:
        def __init__(self, major=3, minor=3, dbg=None):
            self.dbg = dbg
            self.major = major
            self.minor = minor
        def setSock(self, s):
            self.sock = s
        def send(self, msg):
            type = TlsRec_Handshake
            htype = TlsRec_ClientHello
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + (chr(len(msg) & 0xff))  + chr(htype) + msg
            self.sock.sendall(rec)
        def sendMsg(self, msg):
            type=TlsRec_AppData
            rec = chr(type) + chr(self.major) + chr(self.minor) + chr((len(msg) & 0xff00) >> 8) + (chr(len(msg) & 0xff)) + msg
            self.sock.sendall(rec)
        def recv(self):
            headerSz = 6
            rec = ''
            while len(rec) < 5:
                rec += self.sock.recv(5)
            sz = (ord(rec[3])<<8) + ord(rec[4])
            while sz > (len(rec)-headerSz):
                rec += self.sock.recv(sz)
            return rec[6:]
        def recvMsg(self):
            headerSz = 5
            rec = ''
            while len(rec) < 5:
                rec += self.sock.recv(5)
            sz = (ord(rec[3])<<8) + ord(rec[4])
            while sz > (len(rec)-headerSz):
                rec += self.sock.recv(sz)
            return rec[5:]
