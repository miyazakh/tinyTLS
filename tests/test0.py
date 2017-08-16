#!/usr/bin/env python
# coding:UTF-8

import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *


alice = Crypt0(123)
bob   = Crypt0(123)
print str(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
print bob.decrypt(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

nonce = random.randint(1, 15)
print "nonce = " + str(nonce)
alice = Crypt0_ctr(123, nonce)
bob   = Crypt0_ctr(123, nonce)
print str(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
print bob.decrypt(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

nonce = random.randint(1, 15)
print "nonce = " + str(nonce)
alice = Crypt0_gcm(123, nonce, 21)
bob   = Crypt0_gcm(123, nonce, 21)
ret = alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
print str(ret)
print str(bob.decrypt(ret[0], ret[1]))

sha = Sha0()
msg = 'A Big Bad Wolf wants to eat the girl and the food in the basket.'
sha.update(msg)
print str(sha.digest()) + ": " + msg


(pubK, priK) = RsaGenKey(256)
pub = RsaPublic(pubK)
pri = RsaPrivate(priK)

msg = "1234"
sig = pri.sign(msg)
print str(sig)
print "Verify = " + str(pub.verify(msg, sig))

(caPub, caPri) = RsaGenKey(256)
caCert = Cert0(caPub)
caCert.sign(caPri)
caCert.verify(caPub)
print "caCert = " + caCert.dumps()
f = open("./certs/caCert.json", "w")
caCert.dump(f)

svKey = RsaGenKey(256)
svPub = svKey[0]
svPri = svKey[1]
svCert= Cert0(svPub)

svCert.sign(caPri)
print svCert.verify(caPub)
print svCert.verify(caCert.pubKey())

print "svCert = " + svCert.dumps()
f = open("./certs/svCert.json", "w")
svCert.dump(f)

f = open("./certs/svKey.json", "w")
json.dump(svPri, f)

f = open("./certs/caCert.json")
caCert.load(f)
print "caCert = " + caCert.dumps()
f = open("./certs/svCert.json")
svCert.load(f)
print "svCert = " + svCert.dumps()

print svCert.verify(caCert.pubKey())

dhParam = RsaGenKey(256)[0]
dhParam = (1411, 57181)
alice = Dh(dhParam)
bob   = Dh(dhParam)
aPub = alice.genKey(True)
bPub = bob.genKey(True)
print str(alice.agree(bPub)) + " == " + str(bob.agree(aPub))


#RSA key generation
for j in range(0,10):
    pubK, priK = RsaGenKey(256)
    print str((pubK, priK))
    pub = RsaPublic(pubK)
    pri = RsaPrivate(priK)
    for i in range(0, 256):
        if(i != pri.decrypt(pub.encrypt(i))):
            print "ERR" + str(i)
            break
