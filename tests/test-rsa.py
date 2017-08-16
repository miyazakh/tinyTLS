import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *

pubK, priK = RsaGenKey(256)
print str((pubK, priK))
pub = RsaPublic(pubK)
pri = RsaPrivate(priK)
for i in range(0, 256):
    print str((i, pub.encrypt(i), pri.decrypt(pub.encrypt(i))))
    if(i != pri.decrypt(pub.encrypt(i))):
        print "ERR" + str(i)
        break
