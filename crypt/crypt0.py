# crypt0.py
#
# Copyright (C) 2006-2017 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA

#!/usr/bin/env python
# coding:UTF-8

import random
import json

class Crypt0:
    def __init__(self, key):
        """
            simple symmetric encrypt/decrypt class

        Parameters
        ----------
        key : int
            symmetric key for encrypt/decrypt
        """
        self.key = int(key & 0xff)
    def encrypt(self, text):
        """
            encrypt plain text

        Parameters
        ----------
        text : string
            plain text string to be encrypted

        Returns
        -------
        str
            encrypted string
        """
        cipher = ''
        for ch in text:
            cipher +=  chr((ord(ch) ^ self.key))
        return cipher
    def decrypt(self, cipher):
        """
            derypt crypt text

        Parameters
        ----------
        cipher : str
            crypt text string to be decrypted

        Returns
        -------
        str
            plain text string

        """
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
    """ Simple message digest class, returns 8bit digest  """

    def __init__(self):
        self.md = 0x5a
        self.sz = 0
    def update(self, msg):
        """
            add message to dupdate digest

        Parameters
        ----------
            msg : str
                message to add
        """
        for ch in msg:
		    self.md += ord(ch)
        self.sz += len(msg)
    def digest(self):
        """
            return digest value

        Returns
        -------
        int
            digest value

        """
        return (self.md ^ self.sz) & 0xff

class RsaPublic:
    """
        Simple RSA public key class

    Parameters
    ----------
        pub : public key value pair (e, n)
    """
    def __init__(self, pub):
        (self.e, self.n) = pub
    def encrypt(self, num):
        """
            encrypt an integer value with the public key

        Parameters
        ----------
        num : int
            integer value to be encrypted

        Returns
        -------
        int
            encrypted value

        """
        return pow(num, self.e, self.n)
        #return num ** self.e % self.n
    def verify(self, msg, sig):
        """
            velify signature by the public key

        Parameters
        ----------
        msg : str
            signed message string

        sig : int
            signature to be velified

        Returns
        -------
        bool
            True: valid
        """
        md = Sha0()
        md.update(msg)
        return md.digest() == self.encrypt(sig)

class RsaPrivate:
    def __init__(self, pri):
        """
            Simple RSA private key class

        Parameters
        ----------
            pri : private key value pair (d, n)
        """
        (self.d, self.n) = pri
    def decrypt(self, num):
        """
            decrypt integer value with the privale key

        Parameters
        ----------
        num : int
            integer value to be decrypted

        Returns
        -------
        int
            decrypted value

        """
        return pow(num, self.d, self.n)
        #return num ** self.d % self.n
    def sign(self, msg):
        """
            Sign on the message

        Parameters
        ----------
        msg : str
            message to be signed

        Returns
        -------
        int
            Signature value
        """
        md = Sha0()
        md.update(msg)
        return self.decrypt(md.digest())

def RsaGenKey(min):
    """
        Generate an RSA key pair

    Parameters
    ----------
    min : int
        Minimum size of the key value in integer

    Returns
    -------
        Public key (e, n) and Privte key (d, n)
    """
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
        """
            Certificate class

        Parameters
        ----------
            pub : private key value pair (d, n)
            sig : signature
        """
        self.pub = pub
        self.sig = None
    def sign(self, pri):
        """
            Sign with private key

        Parameters
        ----------
            pri : private key value pair (d, n) to sign with
        """
        self.sig = RsaPrivate(pri).sign(json.dumps(self.pub))
    def verify(self, pub):
        """
            Velify certificate with public key

        Parameters
        ----------
            pub : public key value pair (e, n) to sign with

        Returns
        -------
        bool
            True: valid
        """
        return RsaPublic(pub).verify(json.dumps(self.pub), self.sig)
    def pubKey(self):
        """ get public key in the certificate """
        return self.pub
    def dump(self,f):
        """
        serialize the certificate to the file in Json format

        Parameters
        ----------
            f : file descripter to be serialized
        """
        json.dump((self.pub, self.sig), f)
    def dumps(self):
        """
        serialize the certificate to Json format string

        Returns
        ----------
            str : Json format certificate string
        """
        return json.dumps((self.pub, self.sig))
    def load(self, f):
        """
        load the certificate from the file

        Parameters
        ----------
            f : file descripter to be serialized
        """
        cert = json.load(f)
        self.pub = cert[0]
        self.sig = cert[1]
    def loads(self, cert):
        """
        load the certificate from Json format serialized string

        Parameters
        ----------
            cert: certificate string in Json format
        """
        self.pub = json.loads(cert)[0]
        self.sig = json.loads(cert)[1]

class Dh:
    def __init__(self, param):
        """
            Diffie-Hellman key agreement class

        Parameters
        ----------
            param : DH param (g, p)
        """
        (self.g, self.p) = param
    def genKey(self, dbg=None):
        """ generate private and public to peer key """
        self.pri = random.randint(0, 256)
        if(dbg): print "    dh.PRIVATE:" + str(self.pri)
        return pow(self.g, self.pri, self.p)
        #return self.g ** self.pri % self.p
    def agree(self, pub):
        """
        generate agreed value from private and given public key

        Parameters
        ----------
            pub: public key from peer
        """
        return pow(pub, self.pri, self.p)
        #return pub ** self.pri % self.p
