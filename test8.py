#!/usr/bin/env python
# coding:UTF-8

from libttls import *
from rsa   import *

alice = Aes8(123)
bob   = Aes8(123)
print alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
print bob.decrypt(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

sha = Sha8()
sha.update("ABCDEFG")
print sha.digest()


pKey = RsaGenKey(256)
pub = RsaPublic(pKey[0])
pri = RsaPrivate(pKey[1])

for i in range(0,256):
    print pub.encrypt(i)

for i in range(0,256):
    print pri.encrypt(pub.encrypt(i))

msg = 1234
sig = pri.sign(msg)
print str(sig)
if pub.verify(sig) == msg:
    print "Verified"
else:
    print "Failed"

pKey = RsaGenKey(256)
dhParam = pKey[0]
alice = Dh(dhParam)
bob   = Dh(dhParam)
aPub = alice.genKey()
bPub = bob.genKey()
print str(alice.agree(bPub)) + " == " + str(bob.agree(aPub))

＃ RSA key generation
for j in range(0,100):
    pub, pri = RsaGenKey(256)
    print str(pub) + str(pri)
    for i in range(0, 256):
        if(i != pow(pow(i, pub[0], pub[1]), pri[0], pri[1])):
            print "ERR" + str(i)
            break
