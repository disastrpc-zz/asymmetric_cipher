#!/usr/bin/env python

import cryutils, argparse, string, sys, os
from time import perf_counter as prog
from keygen import KeyContainer

def parse():
    parser = argparse.ArgumentParser(prog='pkciph')
    keygen_group = parser.add_mutually_exclusive_group()
    # arg_2 = parser.add_mutually_exclusive_group()
    # out = parser.add_mutually_exclusive_group()


    parser.add_argument('mode',nargs='?')
    keygen_group.add_argument('-l','--lenght',help='Specify key lenght, default is 1024^2 bits',
                    metavar='key size',default=1024,type=int,dest='keysize')
    keygen_group.add_argument('-o','--output',dest='path',
                    help='Output path, default is current directory',metavar='output')
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
    if namespace.mode == 'keygen':
        key_container = KeyContainer(namespace.keysize)
        print("Generating private and public keys with size {}^2 bits...".format(namespace.keysize))
        t_start = prog()
        key_container.generate()
        t_stop = prog()
        key_container.print_key()
        print("Operation successful. Elapsed time {} seconds.".format(int(t_stop - t_start)))


if __name__ == '__main__':
    main()   
