import sys
sys.path.append('./crypt')
from crypt0 import *

md = Sha0()
md.update("A Big Bad Wolf wants to eat the girl and the food in the basket.")
print str(md.digest())
