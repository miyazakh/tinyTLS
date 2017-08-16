import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *

(caPub, caPri) = RsaGenKey(256)
caCert = Cert0(caPub)
caCert.sign(caPri)
caCert.verify(caPub)
print "caCert = " + caCert.dumps()
f = open("./certs/caCert.json", "w")
caCert.dump(f)

svPub, svPri = RsaGenKey(256)
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
