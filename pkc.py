#!/usr/bin/env python

import math
import string
import argparse

CHARSET = string.ascii_letters+string.digits+"@#$%^&*()<>,.?:;[]/!\\\`\'\""+string.whitespace

def main():
    namespace = parse()
    if(namespace.in_path or (namespace.in_path and namespace.out_path)):
        f_cont = get_content(namespace.in_path)
        block = get_block(f_cont)
        print(block)
    elif(namespace.str_stream):
        block = get_block(namespace.str_stream)
        print(block)

def parse():

    parser = argparse.ArgumentParser(prog='pkciph')
    grp_1 = parser.add_mutually_exclusive_group()
    grp_2 = parser.add_mutually_exclusive_group()

    grp_1.add_argument('-f','--file',dest='in_path',
                    help='Provide input file path')
    grp_1.add_argument('-s','--string',dest='str_stream',
                    help='Provide a string')
    grp_2.add_argument('-e','--encrypt',action='store_true',
                    help='Start in encrypt mode')
    grp_2.add_argument('-d','--decrypt',action='store_true',
                    help='Start in decrypt mode')
    parser.add_argument('-o','--output',dest='out_path',
                    help='Provide output path')
    
    namespace = parser.parse_args()
    return namespace

def get_content(in_path):

    stream_open = open(in_path,"r")
    stream_cont = stream_open.read()
    stream_open.close()
    return stream_cont

def get_block(stream):
    raw_block_integer = 0
    exp=0
    for i in stream:
        raw_block_integer += CHARSET.index(i) * (pow(len(CHARSET),exp))
        exp+=1
        print(exp)
    str_block_integer = str(raw_block_integer)
    block_integer = [str_block_integer[i:i+len(CHARSET)] for i in range(0,len(str_block_integer),len(CHARSET))]
    return block_integer


if __name__ == '__main__':
    main()   
