# C = M^e mod n
# M = C^d mod n

import string, math
from keygen import KeyContainer

CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>-=,.?:;[]/!\\\`\'\""+string.whitespace

class _BlockAssembler:

    def __init__(self, stream=0, block_integer=0, raw_block_integer=0, exp=0, str_block_integer=None):
        self.stream = stream
        self.block_integer = block_integer
        self.raw_block_integer = raw_block_integer
        self.str_block_integer = str_block_integer
        self.exp = exp

    def assemble_block(self, stream):
        self.raw_block_integer = 0
        for i in self.stream:
            self.raw_block_integer += CHARSET.index(i) * (pow(len(CHARSET),self.exp))
            self.exp+=1
        self.str_block_integer = str(self.raw_block_integer)
        self.block_integer = [self.str_block_integer[i:i+len(CHARSET)] for i in range(0,len(self.str_block_integer),len(CHARSET))]
        return self.block_integer

class BlockEncrypter:

    def __init__(self,
                stream,
                block_container,
                block_assembler,
                encrypted_block=0, 
                public_key=0, 
                private_key=0, 
                keysize=1024):
        
        self.stream = stream
        self.keysize = keysize
        self.block_assembler = _BlockAssembler()
        self.block_container = block_assembler.assemble_block(self.stream)
        self.encrypted_block = encrypted_block
        self.public_key = public_key
        self.private_key = public_key

    def encrypt(self, public_key):
        for self.block in self.block_container:
            self.encrypted_block = self.block

