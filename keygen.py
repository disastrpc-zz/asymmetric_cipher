# public key = n e
# private key = n d
# gen prime p q
# n = p x q 
# e = e rel prime (p - 1) x (q - 1)
# d = e mod inv 
import cryutils, math, random

def main():
    cont = KeyContainer()
    p = cont.p
    q = cont.q
    e = cont._comp_e(1024)
    print("{} / {} / {}".format(p,q,e))
    print(" ")
    print("Lenght of p: {}".format(len(str(p))))
    print("Lenght of q: {}".format(len(str(q))))
    print("Lenght of e: {}".format(len(str(e))))



class KeyContainer:

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
        self.e = random.randrange((self.p - 1),(self.q - 1))
        return self.e
        
        

if __name__ == "__main__":
    main()

