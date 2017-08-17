import sys
import struct
sys.path.append('./crypt')
sys.path.append('./tls')
from crypt0 import *
from tls_rec import *

class Tls0:
        def __init__(self):
            """
                TLS class for TLS handshake and send/receive messages.
                (This is simplified version of Tls0_cert without Certificate validation)
            """
            self.dbg = None
            self.rec = TlsRecord(3, 3)
        def connect(self, sock, dbg=None):
            """
                Connect to the server.

                Parameters
                ----------
                    sock : TCP connected socket with the server
            """
            # Connect Helpers
            self.dbg = dbg
            self.rec.setSock(sock)
            def sendClientHello():
                if(self.dbg): print "sendClientHello"
                self.rec.send('["ClientHello"]')
            def recvServerHello():
                if(self.dbg): print "recvServerHello"
                return
            def recvServerKeyExchange():
                if(self.dbg): print "recvServerKeyExchenge"
                (dhP, self.svPub) = json.loads(self.rec.recv())
                dhP = (dhP[0], dhP[1])
                self.dh = Dh(dhP)
                if(self.dbg): print "    dh param: "  + str(dhP)
                if(self.dbg): print "    server.public: " + str(self.svPub)
            def sendClientKeyExchange():
                if(self.dbg): print "sendClientKeyExchange"
                pub = self.dh.genKey(self.dbg)
                if(self.dbg): print "    client.public: " + str(pub)
                self.rec.send(json.dumps(pub))
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
            """
                Accept connection from a client

                Parameters
                ----------
                    sock : TCP connected socket with client
            """
            # Accept Helpers
            self.dbg = dbg
            self.rec.setSock(sock)
            def recvClientHello():
                if(self.dbg): print "recvClientHello"
                self.rec.recv()
            def sendServerHello():
                if(self.dbg): print "sendServerHello"
                return
            def sendServerKeyExchange():
                if(self.dbg): print "sendServerKeyExchange"
                dhP = RsaGenKey(256)[0]
                self.dh = Dh(dhP)
                pub = self.dh.genKey(self.dbg)
                self.rec.send(json.dumps((dhP, pub)))
                if(self.dbg): print "    dh param: "  + str(dhP)
                if(self.dbg): print "    server.public: " + str(pub)
            def recvClientKeyExchange():
                if(self.dbg): print "recvClientKeyExchange"
                pub = json.loads(self.rec.recv())
                if(self.dbg): print "    client.public: " + str(pub)
                return self.dh.agree(pub)

            if(self.dbg): print "=== tls.accept ==="
            recvClientHello()
            sendServerHello()
            sendServerKeyExchange()
            premasterSec = recvClientKeyExchange()
            self.msgKey(premasterSec)
            return

        def msgKey(self, sec, dbg=None):
            """
                set premaster secret

                Parameters
                ----------
                    sec : premaster secret
            """
            if(self.dbg): print "    premasterSecret:  " + str(sec)
            self.crypt = Crypt0(sec & 0xff)
        def send(self, msg, dbg=None):
            """
                send application message

                Parameters
                ----------
                    msg : application layer message
            """
            self.rec.sendMsg(self.crypt.encrypt(msg))
            return
        def recv(self, dbg=None):
            """
                receive application message

                Returns
                ----------
                    str : Decrypted received message
            """
            return self.crypt.encrypt(self.rec.recvMsg())
