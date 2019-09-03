#!/usr/bin/env python

import math, cryutils, argparse, string, sys, os
from keygen import KeyContainer

def parse():
    parser = argparse.ArgumentParser(prog='pkciph')
    arg_1 = parser.add_mutually_exclusive_group()
    arg_2 = parser.add_mutually_exclusive_group()
    out = parser.add_mutually_exclusive_group()

    arg_1.add_argument('-f','--file',help='Provide input file path',
                    metavar='<path>')
    arg_1.add_argument('-t','--text',dest='string',
                    help='Provide a string',metavar='<string>')
    arg_1.add_argument('-k','--key',dest='keysize',
                    help='Generate key',type=int,metavar='<keysize>')
    arg_2.add_argument('-e','--encrypt',action='store_true',
                    dest='encrypt',help='Start in encrypt mode')
    arg_2.add_argument('-d','--decrypt',action='store_true',
                    help='Start in decrypt mode')  
    out.add_argument('-o','--output',dest='out',metavar='<output>',
                    help='Output file path')
    namespace = parser.parse_args()
    return namespace

def get_file_content(path):
    stream_open = open(path,"r")
    stream_cont = stream_open.read()
    stream_open.close()
    return stream_cont

def output(path):
    private_path = path
    f = open(path,"x")
    f = open(path,"r+")

def main():
    namespace = parse()
    if namespace.keysize:
        key_container = KeyContainer(namespace.keysize)
        key_container.generate()
        key_container.print_key()
    # elif namespace.keysize and namespace.out:


if __name__ == '__main__':
    main()   
