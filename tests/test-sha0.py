
import sys
sys.path.append('./crypt')
from crypt0 import *

sha = Sha0()
msg = 'A Big Bad Wolf wants to eat the girl and the food in the basket.'
sha.update(msg)
print str(sha.digest()) + ": " + msg
