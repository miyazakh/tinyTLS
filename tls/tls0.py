import sys
sys.path.append('./crypt')
from crypt0 import *

class Tls0:
        def __init__(self):
            self.dbg = None
        def connect(self, sock, dbg=None):
            # Connect Helpers
            self.dbg = dbg
            def sendClientHello():
                if(self.dbg): print "sendClientHello"
                self.sock.sendall("sendClientHello")
            def recvServerHello():
                if(self.dbg): print "recvServerHello"
                return
            def recvServerKeyExchange():
                if(self.dbg): print "recvServerKeyExchenge"
                (dhP, self.svPub) = json.loads(self.sock.recv(32))
                dhP = (dhP[0], dhP[1])
                self.dh = Dh(dhP)
                if(self.dbg): print "    dh param: "  + str(dhP)
                if(self.dbg): print "    server.public: " + str(self.svPub)
            def sendClientKeyExchange():
                if(self.dbg): print "sendClientKeyExchange"
                pub = self.dh.genKey(self.dbg)
                if(self.dbg): print "    client.public: " + str(pub)
                self.sock.sendall(json.dumps(pub))
                return self.dh.agree(int(self.svPub))

            if(self.dbg): print "=== tls.connect ==="
            self.sock = sock
            sendClientHello()
            recvServerHello()
            recvServerKeyExchange()
            premasterSec = sendClientKeyExchange()
            self.msgKey(premasterSec)
            return

        def accept(self, sock, dbg=None):
            # Accept Helpers
            self.dbg = dbg
            def recvClientHello():
                if(self.dbg): print "recvClientHello"
                self.sock.recv(128)
            def sendServerHello():
                if(self.dbg): print "sendServerHello"
                return
            def sendServerKeyExchange():
                if(self.dbg): print "sendServerKeyExchange"
                dhP = RsaGenKey(256)[0]
                self.dh = Dh(dhP)
                pub = self.dh.genKey(self.dbg)
                self.sock.sendall(json.dumps((dhP, pub)))
                if(self.dbg): print "    dh param: "  + str(dhP)
                if(self.dbg): print "    server.public: " + str(pub)
            def recvClientKeyExchange():
                if(self.dbg): print "recvClientKeyExchange"
                pub = json.loads(self.sock.recv(32))
                if(self.dbg): print "    client.public: " + str(pub)
                return self.dh.agree(pub)

            self.sock = sock
            if(self.dbg): print "=== tls.accept ==="
            recvClientHello()
            sendServerHello()
            sendServerKeyExchange()
            premasterSec = recvClientKeyExchange()
            self.msgKey(premasterSec)
            return

        def msgKey(self, sec, dbg=None):
            if(self.dbg): print "    premasterSecret:  " + str(sec)
            self.aes = Aes0(sec & 0xff)
        def send(self, msg, dbg=None):
            self.sock.sendall(self.aes.encrypt(msg))
            return
        def recv(self, sz, dbg=None):
            msg = self.sock.recv(sz)
            return self.aes.encrypt(msg)
