# Key generator module for the Public Key Cipher
#
# Create KeyContainer object and generate public and private keys
# Relies on cryutils.py module
# by Jared @ github.com/disastrpc

import cryutils, math, random

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
    def _comp_n(self, p, q):
        self.n = self.p * self.q
        return self.n
    
    # Compute e
    # e must be relatively prime to x which is calculated using
    # the equation x = (p - 1) * (q - 1)
    def _comp_e(self, p, q, keysize):
        self.x = (self.p - 1) * (self.q - 1)
        while True:  
            # while true try number    
            self.e = random.randrange(2 ** (self.keysize - 1), 2 ** (self.keysize))
            # Check numbers are relative primes
            if(math.gcd(self.e,self.x)==1):
                break
        return self.e

    # Compute d
    # Parameters for the modInverse(a, m) func must be relatively prime.
    def _comp_d(self, e, p, q):
        self.d = cryutils.modInverse(self.e, (self.p - 1) * (self.q - 1))
        return self.d


# KeyContainer child class
# KeyContainer generates and formats private and public keys for display and storage
class KeyContainer(_KeyGenerator):
    
    def __init__(self, keysize, private_key=0, public_key=0):
        self.keysize = keysize
        self.private_key = private_key
        self.public_key = public_key

    # Create KeyGenerator instance and assign keys to instance of KeyContainer object
    def generate(self):
        self.gen = _KeyGenerator(self.keysize)
        self.n = self.gen._comp_n(self.gen.p, self.gen.q)
        self.e = self.gen._comp_e(self.gen.p, self.gen.q, self.keysize)
        self.d = self.gen._comp_d(self.e, self.gen.p, self.gen.q)
        return self.n, self.e, self.d
    
    def print_key(self):
        print("Public key: "+str(self.n)+", "+str(self.e))
        print("Private key: "+str(self.n)+", "+str(self.d))
        print("Public key len: n {} e {}".format(len(str(self.n)), len(str(self.e))))
        print("Private key len: n {} d {}".format(len(str(self.n)), len(str(self.d))))


        

        

        

