#!/usr/bin/env python

import cryutils, argparse, string, sys, os
from time import perf_counter as prog
from helper import Helper
from keygen import KeyContainer
from logging import log
from threading import Thread

def parse():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h','--help',dest='help',action='store_true')
    
    encrypter_group = parser.add_mutually_exclusive_group()

    parser.add_argument('mode',nargs='*')

    # gen mode
    parser.add_argument('-l','--lenght',default=1024,type=int,dest='keysize')
    parser.add_argument('-o','--output',dest='key_output')
    parser.add_argument('--force',action='store_true',dest='force')
    parser.add_argument('--print',action='store_true',dest='print')

    encrypter_group.add_argument('-f','--file',dest='e_path')
    namespace = parser.parse_args()
    return namespace

def get_file_content(path):
    stream_open = open(path,"r")
    stream_cont = stream_open.read()
    stream_open.close()
    return stream_cont

def main():
    namespace = parse()
    if namespace.help:
        Helper.show_help()
    elif 'gen' in namespace.mode:
        key_container = KeyContainer(namespace.keysize)
        sys.stdout.write("Generating private and public keys with size {} bits for p and q...".format(namespace.keysize)+'\n')
        t_start = prog()
        key_container.generate()
        t_stop = prog()
        if namespace.force:
            key_container.to_file(namespace.key_output, overwrite=True)
            Helper.success_timed(t_start, t_stop)
        elif namespace.print:
            sys.stdout.write(key_container.__str__()+'\n')
            Helper.success_timed(t_start, t_stop)
        else:
            key_container.to_file(namespace.key_output)
            Helper.success_timed(t_start, t_stop)
    elif 'en' in namespace.mode:
        sys.stdout.write("encrypting now")

if __name__ == '__main__':
    main()   
