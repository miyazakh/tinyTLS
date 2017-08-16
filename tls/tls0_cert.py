import sys
sys.path.append('./crypt')
from crypt0 import *
sys.path.append('./tls')
from tls_rec import *

class Tls0_cert:
    def __init__(self, cert=None, priK=None, peerC=None):
            self.myCert = cert
            self.priK = priK
            self.peerCert = peerC

    def connect(self, sock, dbg=None):
            # Connect Helpers
        try:
            self.dbg = dbg
            self.rec = TlsRecord(sock, 3,3)
            def sendClientHello():
                if(self.dbg): print "sendClientHello"
                self.rec.send("ClientHello")
            def recvServerHello():
                if(self.dbg): print "recvServerHello"
                return
            def recvCertificate():
                if(self.dbg): print "recvCertificate"
                cert = Cert0()
                cert.loads(self.rec.recv(64))
                if(not cert.verify(self.peerCert.pubKey())):
                    raise Bad_Certificate
            def recvServerKeyExchange():
                if(self.dbg): print "recvServerKeyExchenge"
                (dhP, self.svPub, sig) = json.loads(self.rec.recv(64))
                dhP = (dhP[0], dhP[1])
                pub = RsaPublic(self.peerCert.pubKey())
                if not pub.verify(json.dumps(dhP, self.svPub), sig):
                    print "Invalid Server Key"
                self.dh = Dh(dhP)
                if(self.dbg): print "    dh param: "  + str(dhP)
                if(self.dbg): print "    server.public: " + str(self.svPub)
            def sendClientKeyExchange():
                if(self.dbg): print "sendClientKeyExchange"
                pub = self.dh.genKey(self.dbg)
                if(self.dbg): print "    client.public: " + str(pub)
                self.rec.send(json.dumps(int(pub)))
                return self.dh.agree(int(self.svPub))

            if(self.dbg): print "=== tls.connect ==="
            sendClientHello()
            recvServerHello()
            recvCertificate()
            recvServerKeyExchange()
            premasterSec = sendClientKeyExchange()
            self.msgKey(premasterSec)
            return

        except Bad_Certificate:
            print "ERROR: Bad_Certificate"
            return

    def accept(self, sock, dbg=None):
            # Accept Helpers

            self.dbg = dbg
            self.rec = TlsRecord(sock, 3,3)
            def recvClientHello():
                if(self.dbg): print "recvClientHello"
                self.rec.recv(64)
            def sendServerHello():
                if(self.dbg): print "sendServerHello"
                return
            def sendCertificate():
                if(self.dbg): print "sendCertificate"
                self.rec.send(self.myCert.dumps())
            def sendServerKeyExchange():
                if(self.dbg): print "sendServerKeyExchange"
                dhP = RsaGenKey(256)[0]
                self.dh = Dh(dhP)
                pub = self.dh.genKey(self.dbg)
                sig = self.priK.sign(json.dumps((dhP, pub)))
                self.rec.send(json.dumps((dhP, pub, sig)))
                if(self.dbg): print "    dh param:  "  + str(dhP)
                if(self.dbg): print "    server.pub:" + str(pub)
                if(self.dbg): print "    svKey sig: " + str(sig)
            def recvClientKeyExchange():
                if(self.dbg): print "recvClientKeyExchange"
                pub = json.loads(self.rec.recv(64))
                if(self.dbg): print "    client.pub:" + str(pub)
                return self.dh.agree(pub)

            if(self.dbg): print "=== tls.accept ==="
            recvClientHello()
            sendServerHello()
            sendCertificate()
            sendServerKeyExchange()
            premasterSec = recvClientKeyExchange()
            self.msgKey(premasterSec)
            return

    def msgKey(self, sec, dbg=None):
            if(self.dbg): print "    premasterSec:  " + str(sec)
            self.crypt = Crypt0(sec & 0xff)
    def send(self, msg, dbg=None):
            self.rec.sendMsg(self.crypt.encrypt(msg))
            return
    def recv(self, sz, dbg=None):
            return self.crypt.encrypt(self.rec.recvMsg(sz))
