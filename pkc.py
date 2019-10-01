#!/usr/bin/env python

import cryutils, argparse, string, sys, os
from time import perf_counter as prog
from churner import KeyContainer, BlockHandler
from helper import Helper, HelperThread
from logging import log
from threading import Thread

def gen(keysize=1024):
    keys = KeyContainer(keysize)
    metric_start = prog()
    keys.generate()
    metric_stop = prog()

    if namespace.force:
        keys.to_file(namespace.output, overwrite=True)
    elif namespace.print:
        sys.stdout.write(keys.__str__()+'\n')
    else:
        try:
            keys.to_file(namespace.output)
        except TypeError:
            sys.stderr.write("[ERROR] Please provide a path"+'\n')
        except FileNotFoundError:
            sys.stderr.write("[ERROR] No such file or directory")
    Helper.message_success_timed(metric_start, metric_stop)
            

def en():
    pass

def de():
    pass

SWITCHER = {
    'help': Helper.show_help,
    'gen': gen,
    'en': en,
    'de': de
}
# def parse():
parser = argparse.ArgumentParser(add_help=False)

# mode args
parser.add_argument(dest='mode',choices=SWITCHER.keys())

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

SWITCHER[namespace.mode]()