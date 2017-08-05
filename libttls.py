#!/usr/bin/env python
# coding:UTF-8

import random
import json
from rsa import *

class Aes8:
    def __init__(self, key):
        self.key = int(key)
    def encrypt(self, text):
        cipher = ''
        for ch in text:
            cipher +=  chr((ord(ch) ^ self.key))
        return cipher
    def decrypt(self, cipher):
        text = ''
        for ch in cipher:
            text +=  chr((ord(ch) ^ self.key))
        return text

class Sha8:
    def __init__(self):
        self.md = 0x5a
    def update(self, msg):
	    for ch in msg:
		    self.md = self.md ^ ord(ch)
		    self.md <<= 1
            self.md |= (self.md >> 8) & 0x1
            self.md &= 0xff
    def digest(self):
        return self.md

class RsaPublic:
    def __init__(self, pub):
        self.pub = pub
    def encrypt(self, msg):
        return pow(msg, self.pub[0], self.pub[1])
    def verify(self, sig):
        return self.encrypt(sig)

class RsaPrivate:
    def __init__(self, pri):
        self.pri = pri
    def encrypt(self, msg):
        return pow(msg, self.pri[0], self.pri[1])
    def decrypt(self, msg):
        return pow(msg, self.pri[0], self.pri[1])
    def sign(self, msg):
        return self.decrypt(msg)
    def verify(self, sig):
        return self.encrypt(sig)

class Dh:
    def __init__(self, param):
        self.param = param
        self.pri = 0
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "dh.private:" + str(self.pri)
        return pow(self.param[1], self.pri, self.param[0])
    def agree(self, pub):
        return pow(pub, self.pri, self.param[0])

class Tls0:
        def __init__(self):
            self.dh = None
            self.sock = 0
            self.key = 0
        def connect(self,sock):
            print "=== tls.connect ==="
            self.sock = sock
            sock.sendall(json.dumps("ClientHello"))
            (dhP, pub) = json.loads(sock.recv(32))
            self.dh = Dh(dhP)
            print "dh.public: " + str(pub)
            sock.sendall(json.dumps(self.dh.genKey()))
            agree = self.dh.agree(int(pub))
            print "dh.agree:  " + str(agree)
            self.aes = Aes8(agree & 0xff)
            return
        def accept(self, sock):
            self.sock = sock
            print "=== tls.accept ==="
            self.sock.recv(32)
            dhP = RsaGenKey(256)[0]
            self.dh = Dh(dhP)
            self.sock.sendall(json.dumps((dhP, self.dh.genKey())))
            pub = self.sock.recv(32)
            print "dh.public: " + pub
            agree = self.dh.agree(json.loads(pub))
            print "dh.agree:  " + str(agree)
            self.aes = Aes8(agree & 0xff)
            return
        def send(self, msg):
            self.sock.sendall(self.aes.encrypt(msg))
            return
        def recv(self, sz):
            msg = self.sock.recv(sz)
            ##print "Recv(raw): " + str(msg)
            return self.aes.encrypt(msg)
