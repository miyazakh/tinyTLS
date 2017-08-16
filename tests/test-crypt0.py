import sys
import random
sys.path.append('./crypt')
from crypt0 import *

alice = Crypt0(123)
bob   = Crypt0(123)
print str(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
print bob.decrypt(alice.encrypt("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
