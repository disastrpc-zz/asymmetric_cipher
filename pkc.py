#!/usr/bin/env python

import math, cutils, argparse
import string
import sys, os



CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>,.?:;[]/!\\\`\'\""+string.whitespace

def main():
    namespace = parse()
    block = BlockInteger()
    if(namespace.in_stream or (namespace.in_stream and namespace.out_path)):
        f_cont = get_content(namespace.in_stream)
        block = BlockInteger(f_cont).get_block
        print(block)
    elif(namespace.str_stream):
        block_integer = block.get_block(namespace.str_stream)
        print(block_integer)


def parse():
    parser = argparse.ArgumentParser(prog='pkciph')
    grp_1 = parser.add_mutually_exclusive_group()
    grp_2 = parser.add_mutually_exclusive_group()

    grp_1.add_argument('-f','--file',dest='in_stream',
                    help='Provide input file path')
    grp_1.add_argument('-s','--string',dest='str_stream',
                    help='Provide a string')
    grp_2.add_argument('-e','--encrypt',action='store_true',
                    help='Start in encrypt mode')
    grp_2.add_argument('-d','--decrypt',action='store_true',
                    help='Start in decrypt mode')
    parser.add_argument('-o','--output',dest='out_stream',
                    help='Provide output path')
    
    namespace = parser.parse_args()
    return namespace

def get_content(in_path):
    stream_open = open(in_path,"r")
    stream_cont = stream_open.read()
    stream_open.close()
    return stream_cont

class BlockInteger:

    def __init__(self, stream=None, block_integer=0, raw_block_integer=0, exp=0, str_block_integer=None):
        self.stream = stream
        self.block_integer = block_integer
        self.raw_block_integer = raw_block_integer
        self.str_block_integer = str_block_integer
        self.exp = exp

    def __repr__(self):
        return self.block_integer

    def get_block(self, stream):
        self.raw_block_integer = 0
        for i in stream:
            self.raw_block_integer += CHARSET.index(i) * (pow(len(CHARSET),self.exp))
            self.exp+=1
        self.str_block_integer = str(self.raw_block_integer)
        self.block_integer = [self.str_block_integer[i:i+len(CHARSET)] for i in range(0,len(self.str_block_integer),len(CHARSET))]
        return self.block_integer

#class keyGen:
#    def __init__(self, p, q):
#        self.p = p
#        self.q = q

if __name__ == '__main__':
    main()   
