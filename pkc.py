#!/usr/bin/env python
# Python Implementation of a Public Key Cipher 
# Jared @ github.com/disastrpc

__author__ = 'Jared'
__license__ = 'GNU GPL'

import argparse, string, os, math
from sys import path, stderr, stdout
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
        for block in bar(self.blocks):
            self.cipher_block = pow(int(block), int(self.pub_key[1]), int(self.pub_key[0]))
            self.cipher_blocks.append(self.cipher_block)
        return self.cipher_blocks

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
        a = random.randrange(2, n - 1)
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
        n = random.randrange(2**(s-1), 2**(s))
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
        -l --lenght - specify keylen, if none default of 1024 bits is used
        -o --output - output path
        --force     - overwrite existing key file
        --print     - print keys to screen

    Encrypter
    en
        --privkey   - specify path to private key
        -f --file   - specify path to file

    Decrypter
    de
        --pubkey    - specify path to public key
        -f --file   - specify path to file

    Examples:
    pkc.py gen -l 2048 -o /home/user
    pkc.py en --privkey /root/pk_priv.dat -f myfile.txt
    pkc.py de -f myfile.txt --pubkey /home/user/pk_pub.dat\n''')

    @staticmethod
    def message_finish_timed(t1, t2):
        stdout.write('[INFO] Operation finished. Elapsed time ~{} seconds\n'.format(int(t1 - t2)))

    @staticmethod
    def message_metrics(pub_key, priv_key):
        stdout.write('[INFO] Public key is size {}\n'.format(pub_key))
        stdout.write('[INFO] Private key is size {}\n'.format(priv_key))
        
    @staticmethod
    def message_generate(keysize):
        stdout.write("[INFO] Generating private and public keys with size {} bits for p and q...\n".format(keysize))

# HelperThread objects are used to spawn and kill threads containing messages and animations
class HelperThread(Thread):

    def __init__(self,name,msg,inter=0.065):
        Thread.__init__(self)
        self.name = name
        self.msg = msg
        self.inter = inter
    
    # load specified animation set
    def run(self):
        try:
            while True:
                __class__.load_animation(self.msg, self.inter)
        finally:
            __class__.load_animation(self.msg,self.inter,run=False)

    # get id for each tread
    def get_id(self): 
        for id, thread in Thread._active.items(): 
            if thread is self: 
                return id

    # exits the interpreter 'gracefully' when called
    def kill(self):
        thread_id = self.get_id() 
        res = pythonapi.PyThreadState_SetAsyncExc(thread_id, py_object(SystemExit)) 
        if res > 1: 
            pythonapi.PyThreadState_SetAsyncExc(thread_id, 0) 

    @staticmethod
    def load_animation(msg, inter, run=True):

        # unpack vars
        load_msg, animation = msg, "|/-\\"   
        msg_len = len(load_msg) 
        i, count_time, animation_count = 0,0,0  
        load_str_list = list(load_msg)   
        y = 0     
        while True: 

            # controls animation speed. can be provided to the class instance as inter=int
            sleep(inter)   

            # get ASCII
            x = ord(load_str_list[i])            
            y = 0                             
            if x != 32 and x != 46:              
                if x>90: 
                    y = x-32
                else: 
                    y = x + 32
                load_str_list[i]= chr(y) 

            # to s
            out = ''
            for j in range(msg_len): 
                out += load_str_list[j]   

            stdout.write("\r"+"[INFO] " + out + " " + animation[animation_count]) 
            stdout.flush() 
            load_msg = out 
            animation_count = (animation_count + 1) % 4
            i = (i + 1) % msg_len 
            count_time += 1

            if not run:
                print('\n')
                break

# Main functions
# These are called by the parser object whenever certain args are provided

# Key generation
def gen(keysize=1024):
    keys = KeyContainer(keysize)
    metric_start = prog()
    keys.generate()
    metric_stop = prog()
    try:
        if namespace.force:
            keys.to_file(namespace.output, overwrite=True)
        elif namespace.print:
            stdout.write(keys.__str__()+'\n')
        else:
            keys.to_file(namespace.output)
    except FileExistsError as file_exists_exept:
        stderr.write(str(file_exists_exept))
    except TypeError:
        stderr.write("[ERROR] Please provide an output path")
    finally:
        Helper.message_finish_timed(metric_start, metric_stop)

# Encrypt provided file      
def en():
    pass

def de():
    pass

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
