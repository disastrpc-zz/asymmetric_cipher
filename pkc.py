#!/usr/bin/env python3
# Python Implementation of a Public Key Cipher 
# Jared @ github.com/disastrpc

__author__ = 'Jared'
__license__ = 'GNU GPL'

import argparse, string, os, math, re
from sys import path, stderr, stdout
from numpy import array
from time import perf_counter as prog
from time import sleep
from logging import log
from threading import Thread
from tqdm import tqdm as bar
from random import randrange, random
from pathlib import Path
from numbers import Integral
from itertools import cycle
from ctypes import pythonapi, py_object

# Data churner classes
#
# Generate keys, digest raw or encrypted data and output results
# - Keycontainer child class handles random number generation and computation of n e and d through its parent _KeyGenerator.
#        _comp methods are called by the KeyContainer child class using the generate() method.
#       All _comp methods should be considered implementation details.
# - _BlockAssembler takes raw data and outputs fixed lenght block sizes. This is handled by the __len__ method. 
# - BlockHandler contains encrypt and decrypt methods.
# 
# 2^keylen > CHARSET^len(integer_block) must hold true for each raw block.

class _KeyGenerator:

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

        pub_system_path = os.path.join(path,'pub_key.dat')
        priv_system_path = os.path.join(path,'priv_key.dat')

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

# ----------------------------------------------------------------------------------------------
# Block assembler class takes raw data and transforms it into integer blocks of a fixed lenght. 
# Lenght is determined by the equation in the __len__ method and most hold true for every block.
# 2^keysize > lenght of charset^block size
class _BlockAssembler:

    # Will throw error if data contains text outside charset
    CHARSET_DATA = string.ascii_letters+string.digits+"@#$%^&*()<>-=,.?:;[]/!\\`\'\" "
    CHARSET = []
    for i in CHARSET_DATA:
        CHARSET.append(i)
    CHARSET.append('\n')
    CHARSET.append('\r')

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
        prog = bar(raw_data)
        prog.set_description("[Info] Assembling raw data")
        for i in prog:
            # For index location in character multiply by the len of the charset and an incrementing exponent
            print(i)
            self.raw_integer_block += __class__().CHARSET.index(i) * (pow(len(__class__().CHARSET),self.exp))
            self.exp+=1 
        # print("raw block: " + str(self.raw_integer_block))
        return str(self.raw_integer_block)

    def _disassemble_raw_blocks(self, msg_len, block_size, integer_blocks):
        prog = bar(integer_blocks)
        prog.set_description("[Info] Disassembling integer block")
        msg_len = int(msg_len)
        message = []
        for block in prog:
            block_message = []
            for i in range(block_size - 1, -1, -1):
                if len(message) + i < msg_len:
                    char_index = block // (len(__class__().CHARSET) ** i)
                    print("char index: " + str(char_index))
                    block = block % (len(__class__().CHARSET) ** i)
                    block_message.insert(0, __class__().CHARSET[char_index])
            message.extend(block_message)
        return ''.join(message)
        


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

    def _get_formatted_cipher_blocks(self, cipher_data, block_size):
        return (cipher_data[0+i:block_size+i] for i in range(0, len(str(cipher_data)), block_size))


# BlockHandler holds encrypt and decrypt methods
class BlockHandler(_BlockAssembler):

    def __init__(self,
                raw_integer_block=0,
                block_size=0,
                cipher_blocks=[],
                plain_integer_blocks=[],
                plain_text_blocks=''):
        _BlockAssembler.__init__(self)
        self.raw_integer_block = raw_integer_block.__class__()
        self.block_size = block_size.__class__()
        self.cipher_blocks = cipher_blocks
        self.plain_integer_blocks = plain_integer_blocks
        self.plain_text_blocks = plain_text_blocks

    @staticmethod    
    def split_key(key):
        return key.split(":")
    
    @staticmethod
    def read_content(path):
        content = open(path, 'r')
        stdout.write(f"[Info] Reading content {path}...")
        data = content.read()
        stdout.write("[Info] Done\n")
        content.close()
        return data
       
    def encrypt(self, raw_data, pub_key, output):

        self.raw_data = raw_data

        self.pub_key = self.split_key(pub_key)
        stdout.write("[Info] Formatting blocks...")
        self.blocks = super()._get_formatted_blocks(str(self.raw_data))
        stdout.write("[Info] Done\n")
        prog = bar(self.blocks)
        prog.set_description("[Info] Encrypting blocks")
        for block in prog:
            self.cipher_block = pow(int(block), int(self.pub_key[1]), int(self.pub_key[0]))
            self.cipher_blocks.append(self.cipher_block)
        stdout.write("[Info] Done\n")
        # print("ciph: " + str(self.cipher_blocks))
        return self.cipher_blocks

    def decrypt(self, cipher_data, priv_key, output):     
        self.buf = cipher_data.split('|')
        self.msg_len, self.block_size, self.cipher_data = int(self.buf[0]), int(self.buf[1]), self.buf[2]
        self.cipher_data = self.cipher_data.replace(',','')
        self.cipher_blocks = list(super()._get_formatted_cipher_blocks(self.cipher_data, self.block_size))
        # print(self.cipher_blocks)
        self.priv_key = self.split_key(priv_key)
        prog = bar(self.cipher_blocks)
        prog.set_description("[Info] Decrypting blocks")
        for block in prog:
            self.plain_block = pow(int(block), int(self.priv_key[1]), int(self.priv_key[0]))
            self.plain_integer_blocks.append(self.plain_block)
        self.plain_text = super()._disassemble_raw_blocks(self.msg_len, int(self.block_size), self.plain_integer_blocks)
        return self.plain_text

    def to_encrypted_file(self, path, overwrite=False):

        file_system_path = Path(fr'{path}')

        if not overwrite:
            m = 'x'
        if overwrite:
            m = 'w'
        
        with open(file_system_path, m) as self.cipher_file:
            self.string_cipher_blocks = ','.join(str(i) for i in self.cipher_blocks)
            # self.string_cipher_blocks = re.sub(',','', self.string_cipher_blocks)
            self.cipher_file.write("{}|{}|{}".format(len(self.raw_data), self.block_size, self.string_cipher_blocks))

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


# Helper class creates helper objects to aid in logging and outputting text
class Helper(_KeyGenerator):

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
    pkc.py en --privkey /root/pk_priv.dat -f myfile.txt
    pkc.py de -f myfile.txt --pubkey /home/user/pk_pub.dat\n''')

    @staticmethod
    def measure_time(t1, t2):
        stdout.write('[Info] Elapsed time ~{} seconds.'.format(int(t2 - t1)))

    @staticmethod
    def message_metrics(pub_key, priv_key):
        stdout.write('[Info] Public key is size {}'.format(pub_key))
        stdout.write('[Info] Private key is size {}'.format(priv_key))
        
    @staticmethod
    def message_generate(keysize):
        stdout.write("[Info] Generating private and public keys with size {} bits for p and q...".format(keysize))

# Main functions
# These are called by the parser object whenever certain args are provided
handler = BlockHandler()
# Key generation
def gen(keysize=1024):
    metric_start = prog()
    keys = KeyContainer(namespace.keysize)
    keys.generate()
    try:
        if namespace.force and not namespace.print:
            keys.to_file(namespace.output, overwrite=True)
            stdout.write("[Info] Wrote file to path {}\n".format(namespace.output))
        elif namespace.print and (not namespace.force and namespace.output):
            stdout.write("[Info] Printing key..."+'\n')
            stdout.write(keys.__str__()+'\n')
        elif not namespace.force:
            keys.to_file(namespace.output)
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
    # try:
    metric_start = prog()
    key = handler.read_content(namespace.pub_key)
    raw_data = handler.read_content(namespace.input)
    handler.encrypt(raw_data, key, namespace.output)
    handler.to_encrypted_file(namespace.output)

    # except FileExistsError as file_exists_except:
    #     stderr.write(str(file_exists_except)+'\n')
    # except TypeError as type_except:
    #     stderr.write(str(type_except)+'\n')
    # except Exception as e:
    #     stderr.write(str(e)+'\n')
    # finally:
    #     metric_stop = prog()
    #     Helper.measure_time(metric_start, metric_stop)


def de():
    # try:
    metric_start = prog()
    cipher_data = handler.read_content(namespace.input)
    key = handler.read_content(namespace.priv_key)
    plain_text = handler.decrypt(cipher_data, key, namespace.output)
    handler.to_plain_text_file(namespace.output, plain_text)

    metric_stop = prog()

    # except FileExistsError as file_exists_except:
    #     stderr.write(str(file_exists_except)+'\n')
    # except TypeError as type_except:
    #     stderr.write(str(type_except)+'\n')
    # except Exception as e:
    #     stderr.write(str(e)+'\n')
    # finally:
    #     Helper.measure_time(metric_start, metric_stop)


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
