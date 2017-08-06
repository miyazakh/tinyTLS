from crypt0 import *

class Tls0:
        def __init__(self, cert=None, priK=None, peerC=None):
            self.myCert = cert
            self.priK = priK
            self.peerCert = peerC
            print "peerCert = " + str(peerC)

        def connect(self, sock):
            # Connect Helpers
            def sendClientHello():
                print "sendClientHello"
                self.sock.sendall(json.dumps("ClientHello"))
            def recvServerHello():
                print "recvServerHello"
                return
            def recvCertificate():
                print "recvCertificate"
                cert = Cert0()
                cert.loads(self.sock.recv(32))
                if(not cert.verify(self.peerCert.pubKey())):
                    print "Alert Bad_Certificate"
            def recvServerKeyExchange():
                print "recvServerKeyExchenge"
                (dhP, self.svPub) = json.loads(self.sock.recv(32))
                dhP = (dhP[0], dhP[1])
                self.dh = Dh(dhP)
                print "    dh param: "  + str(dhP)
                print "    server.public: " + str(self.svPub)
            def sendClientKeyExchange():
                print "sendClientKeyExchange"
                pub = self.dh.genKey()
                print "    client.public: " + str(pub)
                self.sock.sendall(json.dumps(int(pub)))
                return self.dh.agree(int(self.svPub))

            print "=== tls.connect ==="
            self.sock = sock
            sendClientHello()
            recvServerHello()
            recvCertificate()
            recvServerKeyExchange()
            masterSec = sendClientKeyExchange()
            self.msgKey(masterSec)
            return

        def accept(self, sock):
            # Accept Helpers
            def recvClientHello():
                print "recvClientHello"
                self.sock.recv(32)
            def sendServerHello():
                print "sendServerHello"
                return
            def sendCertificate():
                print "sendCertificate"
                self.sock.send(self.myCert.dumps())
            def sendServerKeyExchange():
                print "sendServerKeyExchange"
                dhP = RsaGenKey(256)[0]
                self.dh = Dh(dhP)
                pub = self.dh.genKey()
                self.sock.sendall(json.dumps((dhP, pub)))
                print "    dh param: "  + str(dhP)
                print "    server.public: " + str(pub)
            def recvClientKeyExchange():
                print "recvClientKeyExchange"
                pub = self.sock.recv(32)
                print "    client.public: " + str(pub)
                return self.dh.agree(json.loads(pub))

            self.sock = sock
            print "=== tls.accept ==="
            recvClientHello()
            sendServerHello()
            sendCertificate()
            sendServerKeyExchange()
            masterSec = recvClientKeyExchange()
            self.msgKey(masterSec)
            return

        def msgKey(self, sec):
            print "    masterSecret:  " + str(sec)
            self.aes = Aes0(sec & 0xff)
        def send(self, msg):
            self.sock.sendall(self.aes.encrypt(msg))
            return
        def recv(self, sz):
            msg = self.sock.recv(sz)
            return self.aes.encrypt(msg)
