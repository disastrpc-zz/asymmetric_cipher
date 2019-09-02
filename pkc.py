#!/usr/bin/env python

import math, cryutils, argparse, string, sys, os
from encrypter import BlockAssembler

def main():
    namespace = parse()
    block_cont = BlockAssembler()
    if(namespace.in_path or (namespace.in_path and namespace.out_path)):
        f_cont = get_content(namespace.in_stream)
        block_integer = block_cont.assemble_block(f_cont)
        print(block_integer)

    elif(namespace.string):
        block_integer = block_cont.assemble_block(namespace.string)
        print(block_integer)

def parse():
    parser = argparse.ArgumentParser(prog='pkciph')
    grp_1 = parser.add_mutually_exclusive_group()
    grp_2 = parser.add_mutually_exclusive_group()

    grp_1.add_argument('-f','--file',dest='in_path',
                    help='Provide input file path')
    grp_1.add_argument('-s','--string',dest='string',
                    help='Provide a string')
    grp_2.add_argument('-e','--encrypt',action='store_true',
                    help='Start in encrypt mode')
    grp_2.add_argument('-d','--decrypt',action='store_true',
                    help='Start in decrypt mode')
    parser.add_argument('-o','--output',dest='out_path',
                    help='Provide output path')    
    namespace = parser.parse_args()
    return namespace

def get_content(path):
    stream_open = open(path,"r")
    stream_cont = stream_open.read()
    stream_open.close()
    return stream_cont

if __name__ == '__main__':
    main()   
