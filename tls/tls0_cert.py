# ctls0_cert.py
#
# Copyright (C) 2006-2017 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

import sys
sys.path.append('./crypt')
from crypt0 import *
sys.path.append('./tls')
from tls_rec import *

class Tls0_cert:
    def __init__(self, cert=None, priK=None, peerC=None):
        """
            TLS class for TLS handshake and send/receive messages.

            Parameters
            ----------
            cert : Server certificate.
            priK : Server private key.
                   cert and prik are mandate when the class is used for the server side.
            peerC: Certificate to velify peer cert
        """
            self.myCert = cert
            self.priK = priK
            self.peerCert = peerC
            self.rec = TlsRecord(3,3)
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
            def recvCertificate():
                try:
                    if(self.dbg): print "recvCertificate"
                    cert = Cert0()
                    cert.loads(self.rec.recv())
                    if(not cert.verify(self.peerCert.pubKey())):
                        raise Bad_Certificate
                except Bad_Certificate:
                    print "ERROR: Bad_Certificate"
            def recvServerKeyExchange():
                if(self.dbg): print "recvServerKeyExchenge"
                (dhP, self.svPub, sig) = json.loads(self.rec.recv())
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
                self.rec.send(json.dumps(pub))
                return self.dh.agree(int(self.svPub))

            if(self.dbg): print "=== tls.connect ==="
            sendClientHello()
            recvServerHello()
            recvCertificate()
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
            self.dbg = dbg
            self.rec.setSock(sock)
            def recvClientHello():
                if(self.dbg): print "recvClientHello"
                self.rec.recv()
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
                pub = json.loads(self.rec.recv())
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
        """
            set premaster secret

            Parameters
            ----------
                sec : premaster secret
        """
            if(self.dbg): print "    premasterSec:  " + str(sec)
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
