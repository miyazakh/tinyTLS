#!/usr/bin/env python
# coding:UTF-8

import json
import sys
sys.path.append('./crypt')
from crypt0 import *


alice = Aes0(123)
bob   = Aes0(123)
print alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
print bob.decrypt(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))

sha = Sha0()
sha.update("ABCDEFG")
print sha.digest()


pKey = RsaGenKey(256)
pub = RsaPublic(pKey[0])
pri = RsaPrivate(pKey[1])

msg = 1234
sig = pri.sign(msg)
print str(sig)
if pub.verify(sig) == msg:
    print "Verified"
else:
    print "Failed"

pKey = RsaGenKey(256)
caPub = pKey[0]
caPri = pKey[1]
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
aPub = alice.genKey()
bPub = bob.genKey()
print str(alice.agree(bPub)) + " == " + str(bob.agree(aPub))


#RSA key generation
for j in range(0,100):
    pub, pri = RsaGenKey(256)
    print str(pub) + str(pri)
    for i in range(0, 256):
        if(i != pow(pow(i, pub[0], pub[1]), pri[0], pri[1])):
            print "ERR" + str(i)
            break
