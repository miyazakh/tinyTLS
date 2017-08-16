import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *

(pubK, priK) = RsaGenKey(256)
print str((pubK, priK))
pub = RsaPublic(pubK)
pri = RsaPrivate(priK)
msg = 'A Big Bad Wolf wants to eat the girl and the food in the basket.'
print msg
sig = pri.sign(msg)
print str(sig)
print "Verify = " + str(pub.verify(msg, sig))
