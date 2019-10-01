# Data churner module for the Public Key Cipher
#
# Generate keys, digest raw or encrypted data and output results
# - Keycontainer child class handles random number generation and computation of n e and d through its parent _KeyGenerator.
#        _comp methods are called by the KeyContainer child class using the generate() method.
#       All _comp methods should be considered implementation details.
#
# _BlockAssembler takes raw data and outputs fixed lenght block sizes. This is handled by the __len__ method. BlockHandler contains encrypt and decrypt methods.
#       2^keylen > CHARSET^len(integer_block) must hold true.
# Jared @ github.com/disastrpc

__author__ = 'Jared'
__license__ = 'GNU GPL'
__all__ = [
    'KeyContainer',
    'BlockHandler'
]

import string, math, cryutils, os.path
from tqdm import tqdm as prog
from random import randrange
from sys import platform

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
        _KeyGenerator.__init__(self, keysize)
        self.keysize = keysize
        self.priv_key = priv_key
        self.pub_key = pub_key

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

class _BlockAssembler:

    # Will throw error if data contains text outside charset
    CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>-=,.?:;[]/!\\`\'\""+string.whitespace

    def __init__(self, keysize=1024, integer_block=0, block_size=0, raw_integer_block=0, assembled_blocks=0):
        self.keysize = keysize
        self.integer_block = integer_block
        self.block_size = block_size
        self.raw_integer_block = raw_integer_block
        self.assembled_blocks = assembled_blocks

    # Checks for proper lenght of individual blocks
    def __len__(self):
        if pow(2, __class__().keysize) > pow(len(__class__().CHARSET), self.block_size):
            return True
        else:
            return False
    
    # Assemble raw block and return as string
    def _assemble_raw_block(self, raw_data):
        self.exp=0
        for i in raw_data:
            # For index location in character multiply by the len of the charset and an incrementing exponent
            self.raw_integer_block += __class__().CHARSET.index(i) * (pow(len(__class__().CHARSET),self.exp))
            self.exp+=1      
        return str(self.raw_integer_block)

    # Call __len__ to get the maximum block size
    def _get_block_size(self):
        while True:
            if self.__len__() is False:
                return self.block_size
            self.block_size+=1

    # Create generator that returns list with block_size lenght blocks
    def _get_formatted_blocks(self, raw_data):
        self.raw_block, self.block_size = self._assemble_raw_block(raw_data), (self._get_block_size() - 1)
        return [self.raw_block[i:i + self.block_size] for i in range(0, len(self.raw_block), self.block_size)]

# BlockHandler holds encrypt and decrypt methods
class BlockHandler(_BlockAssembler):

    def __init__(self,
                pub_key=0, 
                priv_key=0,
                raw_integer_block=0,
                block_size=0,
                cipher_blocks=[],
                plain_text_blocks=''):
        
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.raw_integer_block = raw_integer_block.__class__()
        self.block_size = block_size.__class__()
        self.cipher_blocks = cipher_blocks
        self.plain_text_blocks = plain_text_blocks

    @staticmethod    
    def split_key(key):
        return key.split(":")
       
    def encrypt(self, raw_data, pub_key, output):
        self.pub_key = self.split_key(pub_key)
        self.blocks = super()._get_formatted_blocks(raw_data)
        for block in prog(self.blocks):
            self.cipher_block = pow(int(block), int(self.pub_key[1]), int(self.pub_key[0]))
            self.cipher_blocks.append(self.cipher_block)
        return self.cipher_blocks

            



