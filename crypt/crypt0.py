#!/usr/bin/env python
# coding:UTF-8

import random
import json

class Aes0:
    def __init__(self, key):
        self.key = int(key & 0xff)
    def encrypt(self, text):
        cipher = ''
        for ch in text:
            cipher +=  chr((ord(ch) ^ self.key))
        return cipher
    def decrypt(self, cipher):
        text = ''
        for ch in cipher:
            text +=  chr((ord(ch) ^ self.key))
        return text
class Aes0_ctr:
        def __init__(self, key, nonce):
            self.key =   key & 0xff
            self.nonce = nonce & 0xff
        def encrypt(self, text):
            cipher = ''
            ctr = (self.nonce  & 0xf) << 0x4
            for ch in text:
                cipher +=  chr((ord(ch) ^ self.key ^ ctr) & 0xff)
                ctr += 1
            return cipher
        def decrypt(self, cipher):
            text = ''
            ctr = (self.nonce  & 0xf) << 0x4
            for ch in cipher:
                text +=  chr((ord(ch) ^ self.key ^ ctr) & 0xff)
                ctr += 1
            return text

class Aes0_gcm:
        def __init__(self, key, nonce, authIn):
            self.key = int(key & 0xff)
            self.nonce = nonce
            self.mult = Sha0()
            self.authIn = authIn & 0xff
        def encrypt(self, text):
            cipher = ''
            ctr = (self.nonce  & 0xf) << 0x4
            self.mult.update(str(self.authIn))
            auth = self.mult.digest()
            for ch in text:
                cipherB = ord(ch) ^ self.key ^ ctr
                cipher += chr(cipherB & 0xff)
                ctr += 1
                self.mult.update(str(auth ^ cipherB))
                auth = self.mult.digest()
            return (cipher, auth)
        def decrypt(self, cipher, authTag):
            text = ''
            ctr = (self.nonce  & 0xf) << 0x4
            self.mult.update(str(self.authIn))
            auth = self.mult.digest()
            for ch in cipher:
                textB = ord(ch) ^ self.key ^ ctr
                text += chr(textB & 0xff)
                ctr += 1
                self.mult.update(str(auth ^ ord(ch)))
                auth = self.mult.digest()
            if(auth == authTag):
                return text
            else: return None

class Sha0:
    def __init__(self):
        self.md = 0x5a
    def update(self, msg):
	    for ch in msg:
		    self.md = self.md ^ ord(ch)
		    self.md <<= 1
            self.md |= (self.md >> 8) & 0x1
            self.md &= 0xff
    def digest(self):
        return self.md

class RsaPublic:
    def __init__(self, pub):
        self.pub = pub
    def encrypt(self, msg):
        return pow(msg, self.pub[0], self.pub[1])
    def verify(self, sig):
        return self.encrypt(sig)

class RsaPrivate:
    def __init__(self, pri):
        self.pri = pri
    def encrypt(self, msg):
        return pow(msg, self.pri[0], self.pri[1])
    def decrypt(self, msg):
        return pow(msg, self.pri[0], self.pri[1])
    def sign(self, msg):
        return self.decrypt(msg)
    def verify(self, sig):
        return self.encrypt(sig)


def RsaGenKey(min):

    def prime(max):
        counter = 0
        primes = [2, 3]
        for n in range(5, max, 2):
          isprime = True
          for i in range(1, len(primes)):
            counter += 1
            if n % primes[i] == 0:
              isprime = False
              break
          if isprime:
            primes.append(n)
        return primes
    def gcd(a, b):
      while b:
        a, b = b, a % b
      return a
    def lcm(x, y):
      return x * y // gcd(x, y)

    primes = prime(1000)
    while True:
        q = primes[random.randint(1, len(primes)-1)]
        p_index = random.randint(1, len(primes)-2)
        p = primes[p_index]
        if p != q: break
    n = p * q
    while(n < min):
        p_index += 1
        p = primes[p_index]
        n = p * q
    l = lcm(p-1, q-1)
    while True:
        i = random.randint(2, l)
        if gcd(i, l) == 1:
            e = i
            break
    while True:
        i = random.randint(2, l)
        if(e*i)%l == 1:
            d = i
            break
    return (e, n), (d, n)

class Cert0:
    def __init__(self, pub=None, sig=None):
        self.pub = pub
        self.sig = None
    def sign(self, pri):
        sha = Sha0()
        sha.update(str(self.pub[0])+str(self.pub[1]))
        digest = sha.digest()
        self.sig = RsaPrivate(pri).sign(digest)
    def verify(self, pub):
        sha = Sha0()
        sha.update(str(self.pub[0])+str(self.pub[1]))
        digest = sha.digest()
        return digest == RsaPublic(pub).verify(self.sig)
    def pubKey(self):
        return self.pub
    def dump(self,f):
        json.dump((self.pub, self.sig), f)
    def dumps(self):
        return json.dumps((self.pub, self.sig))
    def load(self, f):
        cert = json.load(f)
        self.pub = cert[0]
        self.sig = cert[1]
    def loads(self, cert):
        self.pub = json.loads(cert)[0]
        self.sig = json.loads(cert)[1]

class Dh:
    def __init__(self, param):
        self.param = param
        self.pri = 0
    def genKey(self):
        self.pri = random.randint(0, 256)
        print "    dh.PRIVATE:" + str(self.pri)
        return pow(self.param[1], self.pri, self.param[0])
    def agree(self, pub):
        return pow(pub, self.pri, self.param[0])
