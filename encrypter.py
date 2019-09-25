import string, math
from keygen import KeyContainer

class _BlockAssembler:

    CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>-=,.?:;[]/!\\`\'\""+string.whitespace

    def __init__(self, integer_block=0, raw_integer_block=0, keysize=1024, block_size=0):
        self.integer_block = integer_block
        self.raw_integer_block = raw_integer_block
        self.keysize = keysize
        self.block_size = block_size
    
    def __len__(self):
        x, y = pow(2, self.keysize), pow(len(__class__.CHARSET), self.block_size)
        if x >= y:
            return True
        else:
            return False

    # 2^keylen > CHARSET^len(block_integer)
    def _assemble_raw_block(self, raw_data):
        self.exp=0
        for i in raw_data:
            self.raw_integer_block += __class__.CHARSET.index(i) * (pow(len(__class__.CHARSET),self.exp))
            self.exp+=1
        
        return self.raw_integer_block

    def _get_block_len(self):
        while True:
            self.block_size+=1
            print(self.block_size)
            if self.__len__() == False:
                return self.block_size - 1

    
    def _format_block(self):
        block, block_size = self.raw_integer_block, self._get_block_len

# Take block as list and 
class BlockEncrypter(_BlockAssembler):

    def __init__(self,
                stream=0, 
                keysize=0,
                public_key=0, 
                private_key=0):
        
        self.stream = stream
        self.keysize = keysize
        self.assembler = _BlockAssembler()
        self.public_key = public_key
        self.private_key = public_key

    # C = M^e mod n
    # M = C^d mod n
    # def encrypt(self, stream, public_key):
    #     self.public_key = self.public_key.split(':')

    #     for self.block in self.assembler:
    #         self.cipher_block = pow(self.block, )

