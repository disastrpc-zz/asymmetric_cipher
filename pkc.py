#!/usr/bin/env python3
# Python Implementation of a Public Key Cipher 
# Jared @ github.com/disastrpc

__author__ = 'disastrpc'
__license__ = 'GNU GPL'

import argparse, string, os, math, re
from sys import path, stderr, stdout
from numpy import array
from time import perf_counter as prog
from time import sleep
from tqdm import tqdm as bar
from random import randrange, random
from pathlib import Path
from numbers import Integral

# Key container class holds all parts of the key pairs, as well as keysize
class _KeyContainer:

    def __init__(
            self,
            keysize,
            n=0,e=0,d=0,p=0,q=0):
        self.keysize = keysize
        self.p = genPrime(self.keysize)
        self.q = genPrime(self.keysize)
        self.n = n
        self.e = e
        self.d = d

    # print formatted keys
    def __str__(self):
        return "Public key: "+str(self.n)+str(self.e)+'\n'+"Private key: "+str(self.n)+str(self.d)

    # Writes keys to provided path
    def to_file(self, path, overwrite=False):

        pub_system_path = os.path.join(path,'pub_key.dat')
        priv_system_path = os.path.join(path,'priv_key.dat')

        # Used by the --force parameter
        if not overwrite:
            m = 'x'
        if overwrite:
            m = 'w'

        with open(pub_system_path, m) as self.pub_key_file:
            self.pub_key = str(self.keysize)+"::"+str(self.n)+"::"+str(self.e)
            self.pub_key_file.write(self.pub_key)
        with open(priv_system_path, m) as self.priv_key_file:
            self.priv_key = str(self.keysize)+"::"+str(self.n)+"::"+str(self.d)
            self.priv_key_file.write(self.priv_key)

# KeyGenerator stores and formats private and public keys
# The generate method handles the computations and stores them in the _KeyContainer class
class KeyGenerator(_KeyContainer):
    
    def __init__(self, keysize):
        if keysize < 1024:
            stdout.write(f"[Info] Keysize of {keysize} bytes is too small, using size of 1024\n")
            keysize = 1024

        _KeyContainer.__init__(self, keysize)

    def __len__(self, *args):
        for arg in args:
            return len(str(arg))
    # compute n
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
        self.d = modInverse(self.e, (self.p - 1) * (self.q - 1))
        return self.d

    # Calls to all _comp methods to generate key pairs
    def generate(self):
        self.n = self._comp_n()
        self.e = self._comp_e()
        self.d = self._comp_d()
        return self.n, self.e, self.d

# Block assembler class takes raw data and transforms it into integer blocks of a fixed lenght. 
class _BlockAssembler:

    def __init__(self, block_size=0, raw_integer_block=0):
        self.block_size = block_size
        self.raw_integer_block = raw_integer_block

    # Takes original input and assembles into one long string to be processed by the _get_formatted_blocks method
    def _assemble_raw_blocks(self, raw_data):
        # prog = bar(raw_bytes)
        # prog.set_description("[Info] Assembling raw data")
        self.integer_blocks = []

        # convert message to a bytes() object
        self.raw_bytes = raw_data.encode('ascii')

        # init_block declares the index start of the block, up until the block size
        for init_block in range(0, len(self.raw_bytes), self.block_size):
            self.integer_block = 0
            # creates blocks that are block_size in lenght or the lenght of the message
            for i in range(init_block, min(init_block + self.block_size, len(self.raw_bytes))):
                # get ascii code for the character at i index
                self.integer_block += self.raw_bytes[i] * (256 ** (i % self.block_size))
            # code gets converted into a block and appended to the list of blocks
            self.integer_blocks.append(self.integer_block)
        return self.integer_blocks

    # Takes decrypted raw blocks and proccesses them into plain text
    def _disassemble_blocks(self, msg_len, block_size, integer_blocks):
        m = []
        for block in integer_blocks:
            this_message_block = []
            # when decrypting one must start from the last index of the message and count downwards, 
            # which is why the original message lenght is required
            for i in range(block_size - 1, -1, -1):
                if len(m) + i < msg_len:
                    ascii_code = block // (256 ** i)
                    block = block % (256 ** i)
                    # always insert at index 0 since we are counting backwards
                    this_message_block.insert(0, chr(ascii_code))
            m.extend(this_message_block)
        return ''.join(m)

# Handles blocks assembled by BlockAssembler by encrypting, decrypting and outputting to files
class BlockHandler(_BlockAssembler):

    def __init__(self,
                raw_integer_block=0,
                block_size=0):
        _BlockAssembler.__init__(self)
        self.raw_integer_block = raw_integer_block.__class__()
        self.block_size = block_size.__class__()

    @staticmethod    
    def split_key(key):
        return key.split("::")
    
    # reads content to encrypt/decrypt
    @staticmethod
    def read_content(path):
        content = open(path, 'r')
        stdout.write(f"[Info] Reading content {path}...\n")
        data = content.read()
        content.close()
        return data
       
    def encrypt(self, raw_data, pub_key, output, block_size):

        # Split public key into key parts
        self.block_size = block_size
        self.pub_key = self.split_key(pub_key)
        stdout.write("[Info] Formatting blocks...\n")
        if int(self.pub_key[0]) < 1024:
            stdout.write("[Error] Minimum keysize supported is 1024")
            exit()

        """ Encrypting blocks
        Cipher block = C
        Plain text block = M
        Public key[1] = N
        Public key[2] = E
        Then:
        C = M^E mod N
        """
        self.cipher_blocks = []
        for block in super()._assemble_raw_blocks(raw_data):
            self.cipher_blocks.append(pow(int(block), int(self.pub_key[2]), int(self.pub_key[1])))
        return self.cipher_blocks


    def decrypt(self, cipher_data, priv_key, output): 

        # Encrypted text contains information on lenght and size of original message, which is necessary for decoding    
        self.buf = cipher_data.split('::')
        self.msg_len, self.block_size, self.cipher_blocks = int(self.buf[0]), int(self.buf[1]), self.buf[2].split(',')
        self.priv_key = self.split_key(priv_key)

        self.integer_blocks = []
        for block in self.cipher_blocks:  
            """
            Cipher block = C
            Plain text block = M
            Private key[0] = N
            Private key[1] = D
            Then:
            M = C^D mod N
            """
            plain_block = pow(int(block), int(self.priv_key[2]), int(self.priv_key[1]))
            self.integer_blocks.append(plain_block)
        # Call dissasemble method to turn integer blocks back into plain text
        return super()._disassemble_blocks(self.msg_len, self.block_size, self.integer_blocks)

    # Functions to write to files below
    def to_encrypted_file(self, path, overwrite=False):

        file_system_path = Path(fr'{path}')

        if not overwrite:
            m = 'x'
        if overwrite:
            m = 'w'
        
        with open(file_system_path, m) as self.cipher_file:
            self.string_cipher_blocks = ','.join(str(i) for i in self.cipher_blocks)
            # self.string_cipher_blocks = re.sub(',','', self.string_cipher_blocks)
            self.cipher_file.write("{}::{}::{}".format(len(self.raw_bytes), self.block_size, self.string_cipher_blocks))

    def to_plain_text_file(self, path, data):
        file_system_path = Path(fr'{path}')

        with open(file_system_path, 'x') as self.plain_text_file:
            self.plain_text_file.write(data)

        

# -----------------------------------------------------------------------------------------------------------
# Functions to assist in generation of prime numbers for usage in the KeyGenerator and block handler classes

# calculate a sieve of primes and return list
def primeSieve(sieveSize):
    sieve = [True] * sieveSize
    sieve[0] = False
    sieve[1] = False

    #n > 2 < n^sieveSize + 1
    for i in range(2, int(math.sqrt(sieveSize)) + 1):
        pointer = i * 2
        while pointer < sieveSize:
            sieve[pointer] = False
            pointer += 1

    primes = []
    for i in range(sieveSize):
        if sieve[i] == True:
            primes.append(i)
    return primes

# Rabin Miller primality test Python implementation by Al Sweigart
def rabinMiller(n):
    if n % 2 == 0 or n < 2:
        return False
    if n == 3:
        return True
    s = n - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = randrange(2, n - 1)
        v = pow(a, s, n)
        if v != 1:
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % n
    return True

LOW_PRIMES = primeSieve(100)

# func to check if n is prime using lowest 100 prime n
# resorts to rabinMiller() if not found
# faster method than trialDiv() for large ints
def isPrime(n):
    if (n < 2):
        return False
    for prime in LOW_PRIMES:
        if (n % prime == 0):
            return False
    return rabinMiller(n)

# generate primenumber with specified size
# generated number will be s bits in size
# s must be supplied
def genPrime(s):
    while True:
        # generate random number in range of 2^keysize -1 and 2^keysize
        n = randrange(2**(s-1), 2**(s))
        if isPrime(n):
            return n

# return true if n is prime using trial division algorithm
def trialDiv(n):
    # 1 is not prime
    if n < 2:
        return False
    # for every n > 2 < n^2 + 1 
    for i in range(2, int(math.sqrt(n)) + 1):
        #if modulo is 0 n is not prime
        if n % i == 0:
            return False
    # otherwise n is prime
    return True

# mod inverse Python implementation by Al Sweigart
# using the extended Eucledian algorithm
def modInverse(a, m):
    if math.gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1 ,v2, v3
    return u1 % m 
# ----------------------------------------------------------------------------------


# Collection of static methods used to messages
class Helper(_KeyContainer):

    @staticmethod
    def show_help():
        stdout.write('''pkc.py: Public Key Cipher Python implementation
    by Jared Freed | https://github.com/disastrpc/pkc
    Usage:

    pkc.py [mode] [args]

    Modes:

    Key generator
    gen
        -l --lenght     - specify keylen, if none default of 1024 bits is used
        -o --output     - output path
        --force         - overwrite existing key file
        --print         - print keys to screen

    Encrypter
    en
        --publickey     - specify path to public key
        -f --file       - specify path to file
        -o, --output    - specify output path

    Decrypter
    de
        --privatekey    - specify path to private key
        -f --file       - specify path to file
        -o, --output    - specify output path

    Examples:
    pkc.py gen -l 2048 -o /home/user
    pkc.py en --publickey /root/pub_key.dat -f myfile.txt
    pkc.py de -f my_encrypted_file.txt --privatekey /home/user/priv_key.dat\n''')

    @staticmethod
    def measure_time(t1, t2):
        stdout.write('[Info] Elapsed time ~{} seconds.\n'.format(int(t2 - t1)))

    @staticmethod
    def message_metrics(pub_key, priv_key):
        stdout.write('[Info] Public key is size {}\n'.format(pub_key))
        stdout.write('[Info] Private key is size {}\n'.format(priv_key))
        
    @staticmethod
    def message_generate(keysize):
        stdout.write("[Info] Generating private and public keys with size {} bits for p and q...\n".format(keysize))

# Main functions
# These are called by the parser object whenever certain args are provided
handler = BlockHandler()
# Key generation
def gen(keysize=1024):
    metric_start = prog()
    generator = KeyGenerator(namespace.keysize)
    generator.generate()
    try:

        if namespace.output and namespace.force:
            generator.to_file(namespace.output, overwrite=True)
            stdout.write("[Info] Wrote file to path {}\n".format(namespace.output))
        elif namespace.print and (not namespace.force and not namespace.output):
            stdout.write("[Info] Printing keys..."+generator.__str__()+'\n')
        elif namespace.output and not namespace.force:
            generator.to_file(namespace.output)
            stdout.write("[Info] Wrote file to path {}\n".format(namespace.output))
        else:
            raise Exception("[Err] Generation failed, invalid parameters. Enter 'help' for usage.\n")

    except FileExistsError as file_exists_except:
        stderr.write(str(file_exists_except)+'\n')
    except TypeError as type_except:
        stderr.write(str(type_except)+'\n')
    except Exception as e:
        stderr.write(str(e)+'\n')
    finally:
        metric_stop = prog()
        Helper.measure_time(metric_start, metric_stop)

# Encrypt provided file      
def en():
    try:
        metric_start = prog()
        key = handler.read_content(namespace.pub_key)
        raw_data = handler.read_content(namespace.input)
        handler.encrypt(raw_data, key, namespace.output, block_size=128)
        handler.to_encrypted_file(namespace.output)

    except FileExistsError as file_exists_except:
        stderr.write(str(file_exists_except)+'\n')
    except TypeError as type_except:
        stderr.write(str(type_except)+'\n')
    except Exception as e:
        stderr.write(str(e)+'\n')
    finally:
        metric_stop = prog()
        Helper.measure_time(metric_start, metric_stop)


def de():
    try:

        metric_start = prog()
        cipher_data = handler.read_content(namespace.input)
        key = handler.read_content(namespace.priv_key)
        plain_text = handler.decrypt(cipher_data, key, namespace.output)
        handler.to_plain_text_file(namespace.output, plain_text)

    except FileExistsError as file_exists_except:
        stderr.write(str(file_exists_except)+'\n')
    except TypeError as type_except:
        stderr.write(str(type_except)+'\n')
    except Exception as e:
        stderr.write(str(e)+'\n')
    finally:
        metric_stop = prog()
        Helper.measure_time(metric_start, metric_stop)


INIT = {
    'help': Helper.show_help,
    'gen': gen,
    'en': en,
    'de': de
}

# def parse():
parser = argparse.ArgumentParser(add_help=False)

# mode args
parser.add_argument(dest='mode',choices=INIT.keys())

# gen mode
parser.add_argument('-l','--lenght',default=1024,type=int,dest='keysize')
parser.add_argument('-o','--output',dest='output')
parser.add_argument('--force',action='store_true',dest='force')
parser.add_argument('--print',action='store_true',dest='print')

# en/de mode
parser.add_argument('-f','--file',dest='input')
parser.add_argument('--privatekey',dest='priv_key')
parser.add_argument('--publickey',dest='pub_key')
namespace = parser.parse_args()
         
INIT[namespace.mode]()
