#!/usr/bin/env python
# coding:UTF-8

from tls00 import *

alice = Aes()
bob   = Aes()

alice.key(123)
bob.  key(123)
print alice.enc("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
print bob.enc(alice.enc("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

print Digest().sha8("ABCDEFG")

pubKey = RsaKey(5, 323)
priKey = RsaKey(29, 323)

for i in range(0,255):
    print pubKey.encrypt(i)

for i in range(0,255):
    print priKey.encrypt(pubKey.encrypt(i))

sig = Sig().sign(priKey, "ABCDEFG")
print Sig().verify(pubKey, sig, "ABCDEFG")

dhParam = RsaKey(13, 2)
alice = Dh(dhParam)
bob   = Dh(dhParam)
aPub = alice.genKey()
bPub = bob.genKey()
print alice.agree(bPub)
print bob.agree(aPub)
