# public key = n e
# private key = n d
# gen prime p q
# n = p x q 
# e = e rel prime (p - 1) x (q - 1)
# d = e mod inv 
import cryutils, math, random

class _ComputeKey:

    def __init__(
            self,
            public_key=0, 
            private_key=0, 
            keysize=1024,
            n=0,e=0,d=0,p=0,q=0):

        self.public_key = public_key
        self.private_key = private_key
        self.keysize = keysize
        self.n = n
        self.e = e
        self.d = d
        self.p = cryutils.genPrime(self.keysize)
        self.q = cryutils.genPrime(self.keysize)
    
    def _comp_n(self, n, p, q):
        self.n = self.p * self.q
        return self.n
    
    def _comp_e(self, keysize):
        self.x = (self.p - 1) * (self.q - 1)
        print(" " + str(self.x) + " ")
        if (self.p > self.q): 
            while True:      
                self.e = random.randrange(self.q, self.p)
                if(math.gcd(self.e,self.x)==1):
                    break
            return self.e
        else:
            while True:
                self.e = random.randrange(self.p, self.q)
                if(math.gcd(self.e,self.x)==1):
                    break
            return self.e
    
    def _comp_d(self, d, e, p, q):
        self.d = cryutils.modInverse(self.e, (self.p - 1) * (self.q - 1))
        return self.d

class KeyContainer(_ComputeKey):
    
    def generate():
        k = _ComputeKey()
        

