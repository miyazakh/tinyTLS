import random

class Digest:
    def sha8(self, msg):
	    md = 0x5a
	    for ch in msg:
		    md = md ^ ord(ch)
		    md <<= 1
            md |= (md >> 8) & 0x1
            md &= 0xff
	    return md

Digest().sha8("ABCDEFG")

class RsaKey:
    def __init__(self, g=0, p=0):
        self.g = g
        self.p = p
    def encrypt(self, msg): 
        return msg ** self.g % self.p

pubKey = RsaKey(5, 323)

priKey = RsaKey(29, 323)

for i in range(0,255):pubKey.encrypt(i)

for i in range(0,255):priKey.encrypt(pubKey.encrypt(i))


class Sig:
    def sign(self, priKey, msg): 
        return priKey.encrypt(Digest().sha8(msg))
    
    def verify(self, pubKey, sig, msg): 
        return pubKey.encrypt(sig) == Digest().sha8(msg)

sig = Sig().sign(priKey, "ABCDEFG")
Sig().verify(pubKey, sig, "ABCDEFG")


class Dh:
    def __init__(self, dhParam):
        self.dhParam = dhParam
    
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "private key = " + str(self.pri)
        return dhParam.p ** self.pri % self.dhParam.g
    
    def agree(self, pub):
        return pub ** self.pri % self.dhParam.g

dhParam = RsaKey(13, 2)
alice = Dh(dhParam)
bob   = Dh(dhParam)
aPub = alice.genKey()
bPub = bob.genKey()
alice.agree(bPub)
bob.agree(aPub)
