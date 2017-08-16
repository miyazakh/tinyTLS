import json
import sys
import random
sys.path.append('./crypt')
from crypt0 import *


dhParam = (3, 57181)
alice = Dh(dhParam)
bob   = Dh(dhParam)
aPub = alice.genKey(True)
bPub = bob.genKey(True)
print str(alice.agree(bPub)) + " == " + str(bob.agree(aPub))
