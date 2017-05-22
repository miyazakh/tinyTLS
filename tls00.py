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
    def __init__(self, dhParam):
        self.dhParam = dhParam
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "private key = " + str(self.pri)
        return self.dhParam.p ** self.pri % self.dhParam.g
    def agree(self, pub):
        return pub ** self.pri % self.dhParam.g
