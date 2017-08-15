import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *

(pubK, priK) = RsaGenKey(256)
print str((pubK, priK))
pub = RsaPublic(pubK)
pri = RsaPrivate(priK)

while True:
    line = raw_input()
    sig = pri.sign(line)
    print str(sig)
    print "Verify = " + str(pub.verify(line, sig))
