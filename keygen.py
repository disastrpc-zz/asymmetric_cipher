# public key = n e
# private key = n d
# gen prime p q
# n = p x q 
# e = e rel prime (p - 1) x (q - 1)
# d = e mod inv 
import cryutils, math, random

class _KeyGenerator:

    def __init__(
            self,
            keysize=1024,
            n=0,e=0,d=0,p=0,q=0):

        self.keysize = keysize
        self.n = n
        self.e = e
        self.d = d
        self.p = cryutils.genPrime(self.keysize)
        self.q = cryutils.genPrime(self.keysize)
    
    def _comp_n(self, p, q):
        self.n = self.p * self.q
        return self.n
    
    def _comp_e(self, p, q):
        self.x = (self.p - 1) * (self.q - 1)
        if (self.p > self.q): 
            while True:      
                self.e = random.randrange(self.q, self.p) # ?
                if(math.gcd(self.e,self.x)==1):
                    break
            return self.e
        else:
            while True:
                self.e = random.randrange(self.p, self.q) # ?
                if(math.gcd(self.e,self.x)==1):
                    break
            return self.e
    
    def _comp_d(self, e, p, q):
        self.d = cryutils.modInverse(self.e, (self.p - 1) * (self.q - 1))
        return self.d

class KeyContainer(_KeyGenerator):
    
    def __init__(self, private_key=0, public_key=0):
        self.private_key = private_key
        self.public_key = public_key
    
    def generate(self):
        self.gen = _KeyGenerator()
        self.n = self.gen._comp_n(self.gen.p, self.gen.q)
        self.e = self.gen._comp_e(self.gen.p, self.gen.q)
        self.d = self.gen._comp_d(self.e, self.gen.p, self.gen.q)
        return self.n, self.e, self.d

def main():
    keygen = _KeyGenerator()
    n = keygen._comp_n(keygen.p, keygen.q)
    print(n)
    e = keygen._comp_e(keygen.p, keygen.q)
    print(e)
    d = keygen._comp_d(e, keygen.p, keygen.q)
    print(d)

if __name__ == "__main__":
    main()
        

        

        

