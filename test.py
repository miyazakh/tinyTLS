#!/usr/bin/env python
# coding:UTF-8

from tls00 import *
from rsa   import *

alice = Aes()
bob   = Aes()

alice.setkey(123)
bob.  setKey(123)
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
alice = Dh()
bob   = Dh()
alice.param(dhParam)
bob.  param(dhParam)
aPub = alice.genKey()
bPub = bob.genKey()
print alice.agree(bPub)
print bob.agree(aPub)

＃ RSA key generation
for j in range(0,100):
    pub, pri = RsaGenKey(256)
    print str(pub) + str(pri)
    for i in range(0, 256):
        if(i != pow(pow(i, pub[0], pub[1]), pri[0], pri[1])):
            print "ERR" + str(i)
            break
