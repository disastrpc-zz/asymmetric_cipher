import string, math
from keygen import KeyContainer

# Takes  

class _BlockContainer:

    def __init__(self, keysize=1024, assembled_blocks=0, block_size=0):
        self.assembled_blocks = assembled_blocks
        self.keysize = keysize
        self.block_size = block_size

class _BlockAssembler(_BlockContainer):

    CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>-=,.?:;[]/!\\`\'\""+string.whitespace

    def __init__(self, integer_block=0, raw_integer_block=0):
        self.integer_block = integer_block
        self.raw_integer_block = raw_integer_block

    def __len__(self):
        if pow(2, self.keysize) > pow(len(__class__.CHARSET), self.block_size):
            return True
        else:
            return False
    
    # 2^keylen > CHARSET^len(block_integer)
    def _assemble_raw_block(self, raw_data):
        self.exp=0
        for i in raw_data:
            self.raw_integer_block += __class__.CHARSET.index(i) * (pow(len(__class__.CHARSET),self.exp))
            self.exp+=1
        
        return str(self.raw_integer_block)

    def _get_block_size(self):
        while True:
            if self.__len__() == False:
                return self.block_size
            self.block_size+=1


    def _format_block(self, raw_data):
        self.block, self.block_size = self._assemble_raw_block(raw_data), (self._get_block_size() - 1)
        return [self.block[i:i + self.block_size - 1] for i in range(0, len(self.block), self.block_size)]



# Take block as list and 
class BlockEncrypter(_BlockAssembler):

    def __init__(self,
                public_key='', 
                private_key=''):
        
        self.public_key = public_key
        self.private_key = public_key

    # C = M^e mod n
    # M = C^d mod n
    def encrypt(self, raw_data, public_key):
        self.public_key_arr = self.public_key.split(':')
        block = super()._format_block(raw_data)

        print(self.public_key[0])
        print(self.public_key[1])

