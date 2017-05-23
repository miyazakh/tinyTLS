#!/usr/bin/env python
# coding:UTF-8

import random

class Aes:
    key = 0
    def key(self, key):
        self.key = key
    def enc(self, In):
        Out = ''
        for ch in In:
            Out +=  chr((ord(ch) ^ self.key))
        return Out

class Digest:
    def sha8(self, msg):
	    md = 0x5a
	    for ch in msg:
		    md = md ^ ord(ch)
		    md <<= 1
            md |= (md >> 8) & 0x1
            md &= 0xff
	    return md


class RsaKey:
    def __init__(self, g=0, p=0):
        self.g = g
        self.p = p
    def encrypt(self, msg):
        return msg ** self.g % self.p

class Sig:
    def sign(self, priKey, msg):
        return priKey.encrypt(Digest().sha8(msg))
    def verify(self, pubKey, sig, msg):
        return pubKey.encrypt(sig) == Digest().sha8(msg)

class Dh:
    def __init__(self):
        self.dhParam = RsaKey(0,0)
    def param(self, param):
        self.dhParam = param
        return
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "private key = " + str(self.pri)
        return self.dhParam.p ** self.pri % self.dhParam.g
    def agree(self, pub):
        return pub ** self.pri % self.dhParam.g

class tTls:
        def __init__(self):
            self.dh = Dh()
            self.dh.param(RsaKey(13, 2))
            self.aes = Aes()
            self.sock = 0;
            self.key = 0
        def connect(self,sock):
            print "tls.connect"
            self.sock = sock
            sock.sendall("ClientHello")
            sock.sendall(str(self.dh.genKey()))
            pub = sock.recv(32)
            print pub
            self.aes.key(int(self.dh.agree(int(pub))))
            return
        def accept(self, sock):
            self.sock = sock
            print "tls.accept"
            print sock.recv(32)
            sock.sendall(str(self.dh.genKey()))
            pub = sock.recv(32)
            print pub
            self.aes.key(int(self.dh.agree(int(pub))))
            return
        def send(self, msg):
            self.sock.sendall(self.aes.enc(msg))
            return
        def recv(self, len):
            return self.aes.enc(self.sock.recv(len))
