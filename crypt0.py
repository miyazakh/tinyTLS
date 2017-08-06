#!/usr/bin/env python
# coding:UTF-8

import random
import json
from rsa import *

class Aes0:
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

class Sha0:
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

class Cert0:
    def __init__(self, pub=None, sig=None):
        self.pub = pub
        self.sig = None
    def sign(self, pri):
        sha = Sha0()
        sha.update(str(self.pub[0])+str(self.pub[1]))
        digest = sha.digest()
        self.sig = RsaPrivate(pri).sign(digest)
    def verify(self, pub):
        sha = Sha0()
        sha.update(str(self.pub[0])+str(self.pub[1]))
        digest = sha.digest()
        return digest == RsaPublic(pub).verify(self.sig)
    def pubKey(self):
        return self.pub
    def dump(self,f):
        json.dump((self.pub, self.sig), f)
    def dumps(self):
        return json.dumps((self.pub, self.sig))
    def load(self, f):
        cert = json.load(f)
        self.pub = cert[0]
        self.sig = cert[1]
    def loads(self, cert):
        self.pub = json.loads(cert)[0]
        self.sig = json.loads(cert)[1]

class Dh:
    def __init__(self, param):
        self.param = param
        self.pri = 0
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "    dh.PRIVATE:" + str(self.pri)
        return pow(self.param[1], self.pri, self.param[0])
    def agree(self, pub):
        return pow(pub, self.pri, self.param[0])
