#!/usr/bin/env python

import cryutils, argparse, string, sys, os
from time import perf_counter as prog
from encrypter import _BlockAssembler, BlockEncrypter
from helper import Helper
from keygen import KeyContainer
from logging import log
from threading import Thread

def parse():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h','--help',dest='help',action='store_true')

    # mode arg
    parser.add_argument('mode',nargs='*')

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
    return namespace

def main():
    namespace = parse()
    if namespace.help:
        Helper.show_help()
    elif 'gen' in namespace.mode:
        key_container = KeyContainer(namespace.keysize)
        Helper.message_generate(namespace.keysize)
        t_start = prog()
        key_container.generate()
        t_stop = prog()
        if namespace.force:
            key_container.to_file(namespace.output, overwrite=True)
            Helper.message_success_timed(t_start, t_stop)
        elif namespace.print:            
            sys.stdout.write(key_container.__str__()+'\n')
            Helper.message_success_timed(t_start, t_stop)
        else:
            key_container.to_file(namespace.output)
            Helper.message_success_timed(t_start, t_stop)
    elif 'en' in namespace.mode:
        kf = open(namespace.pub_key,'r')
        pub_key_path = kf.read()
        kf.close()
        
        with open(namespace.input,'r') as f:
            raw_data = f.read()
            encrypter = BlockEncrypter()
            encrypter.encrypt(raw_data, pub_key_path)


if __name__ == '__main__':
    main()   
