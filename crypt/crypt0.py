#!/usr/bin/env python
# coding:UTF-8

import random
import json

class Crypt0:
    def __init__(self, key):
        self.key = int(key & 0xff)
    def encrypt(self, text):
        cipher = ''
        for ch in text:
            cipher +=  chr((ord(ch) ^ self.key))
        return cipher
    def decrypt(self, cipher):
        return self.encrypt(cipher)

class Crypt0_ctr:
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
        return self.encrypt(cipher)

class Crypt0_gcm:
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
        self.sz = 0
    def update(self, msg):
	    for ch in msg:
		    self.md += ord(ch)
	    self.sz += len(msg)
    def digest(self):
        return (self.md ^ self.sz) & 0xff

class RsaPublic:
    def __init__(self, pub):
        (self.e, self.n) = pub
    def encrypt(self, num):
        return num ** self.e % self.n
    def verify(self, msg, sig):
        md = Sha0()
        md.update(msg)
        return md.digest() == self.encrypt(sig)

class RsaPrivate:
    def __init__(self, pri):
        (self.d, self.n) = pri
    def decrypt(self, num):
        return num ** self.d % self.n
    def sign(self, msg):
        md = Sha0()
        md.update(msg)
        return self.decrypt(md.digest())

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
        self.sig = RsaPrivate(pri).sign(json.dumps(self.pub))
    def verify(self, pub):
        return RsaPublic(pub).verify(json.dumps(self.pub), self.sig)
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
        (self.g, self.p) = param
    def genKey(self, dbg=None):
        self.pri = random.randint(0, 256)
        if(dbg): print "    dh.PRIVATE:" + str(self.pri)
        return self.g ** self.pri % self.p
    def agree(self, pub):
        return pub ** self.pri % self.p
