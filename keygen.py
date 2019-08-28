# public key = n e
# private key = n d
# gen prime p q
# n = p x q 
# e = e rel prime (p - 1) x (q - 1)
# d = e mod inv 
import cutils, math
from tqdm import tqdm as prog

def main():
    cont = KeyContainer()
    p = cutils.genPrime()
    q = cutils.genPrime()
    print(p,q)


class KeyContainer:

    def __init__(
        self,
        public_key=0, 
        private_key=0, 
        n=0,e=0,d=0):

        self.public_key = public_key
        self.private_key = private_key
        self.n = n
        self.e = e
        self.d = d


if __name__ == "__main__":
    main()

