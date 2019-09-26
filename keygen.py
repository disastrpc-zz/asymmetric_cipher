# Key generator module for the Public Key Cipher
#
# Create KeyContainer object and generate public and private keys
# Relies on cryutils.py module
# by Jared @ github.com/disastrpc

import cryutils, math, os.path
from random import randrange
from sys import platform

# _KeyGenerator parent class handles random number generation and computation of n e and d
# _comp methods are called by the KeyContainer child class using the generate() method
# All _comp methods should be considered implementation details.

class _KeyGenerator:

    def __init__(
            self,
            keysize,
            n=0,e=0,d=0,p=0,q=0):

        self.keysize = keysize
        self.p = cryutils.genPrime(self.keysize)
        self.q = cryutils.genPrime(self.keysize)
        self.n = n
        self.e = e
        self.d = d
    
    # compute n using equation n = p * q
    def _comp_n(self):
        self.n = self.p * self.q
        return self.n
    
    # Compute e
    # e must be relatively prime to p*q which is calculated using
    # the equation e = (p - 1) * (q - 1)
    def _comp_e(self):
        while True:  
            # while true try number    
            self.e = randrange(2 ** (self.keysize - 1), 2 ** (self.keysize))
            # Check numbers are relative primes
            if(math.gcd(self.e,(self.p - 1) * (self.q - 1))==1):
                return self.e

    # Compute d
    # Parameters for the modInverse(a, m) func must be relatively prime.
    def _comp_d(self):
        self.d = cryutils.modInverse(self.e, (self.p - 1) * (self.q - 1))
        return self.d

    # Create KeyGenerator instance and assign keys to instance of object
    def generate(self):
        self.gen = _KeyGenerator(self.keysize)
        self.n = self.gen._comp_n()
        self.e = self.gen._comp_e()
        self.d = self.gen._comp_d()
        return self.n, self.e, self.d

# KeyContainer generates and formats private and public keys for display and storage
class KeyContainer(_KeyGenerator):
    
    def __init__(self, keysize, priv_key=0, pub_key=0):
        self.keysize = keysize
        self.priv_key = priv_key
        self.pub_key = pub_key
    
    def __repr__(self):
        return '{self.__class__.__name__}({self.keysize},{self.priv_key},{self.pub_key})'.format(self=self)
    
    def __str__(self):
        return "Public key: "+str(self.n)+str(self.e)+'\n'+"Private key: "+str(self.n)+str(self.d)

    def __len__(self, *args):
        for arg in args:
            return len(str(arg))

    def to_file(self, path, overwrite=False):

        pub_system_path = os.path.join(path,'pk_pub.dat')
        priv_system_path = os.path.join(path,'pk_priv.dat')

        if not overwrite:
            m = 'x'
        if overwrite:
            m = 'w'

        with open(pub_system_path, m) as self.pub_key_file:
            self.pub_key = str(self.n)+":"+str(self.e)
            self.pub_key_file.write(self.pub_key)
        with open(priv_system_path, m) as self.priv_key_file:
            self.priv_key = str(self.n)+":"+str(self.d)
            self.priv_key_file.write(self.priv_key)
            
