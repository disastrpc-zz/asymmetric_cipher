# Encrypter module for the Public Key Cipher
#
# Digest raw or encrypted data and output results
# Jared @ github.com/disastrpc

import string, math
from keygen import KeyContainer

# BlockAssembler takes raw data and outputs fixed lenght block sizes. This is handled by the __len__ method.
# 2^keylen > CHARSET^len(integer_block) must hold true.
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
        self.block, self.block_size = self._assemble_raw_block(raw_data), (self._get_block_size() - 1)
        return [self.block[i:i + self.block_size] for i in range(0, len(self.block), self.block_size)]

# BlockEncrypter holds encrypt and decrypt methods
class BlockEncrypter(_BlockAssembler):

    def __init__(self,
                public_key='', 
                private_key='',
                raw_integer_block=0,
                block_size=0):
        
        self.public_key = public_key
        self.private_key = public_key
        self.raw_integer_block = raw_integer_block.__class__()
        self.block_size = block_size.__class__()
        

    # C = M^e mod n
    # M = C^d mod n
    def encrypt(self, raw_data, public_key):
        self.public_key_arr = self.public_key.split(':')
        block = super()._get_formatted_blocks(raw_data)
        print(block[2])
