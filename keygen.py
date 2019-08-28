# public key = n e
# private key = n d
# gen prime p q
# n = p x q 
# e = e rel prime (p - 1) x (q - 1)
# d = e mod inv 

class KeyContainer:

    def __init__(self, public_key, private_key, keysize):
        self.public_key = public_key
        self.private_key = private_key
        self.keysize = keysize

    