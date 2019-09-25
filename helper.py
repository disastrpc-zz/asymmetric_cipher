from keygen import KeyContainer, _KeyGenerator
from numbers import Integral
from itertools import cycle
from threading import Thread
from time import sleep
from sys import stdout

# Helper class creates helper objects to aid in logging and outputting text
# Contains --help for pkc
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
    pkc.py de -f myfile.txt --pubkey /home/user/pk_pub.dat''')

    @staticmethod
    def message_success_timed(t_start, t_stop):
        stdout.write("[INFO] Operation successful. Elapsed time ~{} seconds.".format(int(t_stop - t_start))+'\n')

    @staticmethod
    def message_metrics(pub_key, priv_key):
        stdout.write('[INFO] Public key is size {} \n'.format(pub_key))
        stdout.write('[INFO] Private key is size {} \n'.format(priv_key))
        
    @staticmethod
    def message_generate(keysize):
        stdout.write("[INFO] Generating private and public keys with size {} bits for p and q...".format(keysize)+'\n')

    @staticmethod
    def animate():
        brk = False
        for c in cycle(['|', '/', '-', '\\']):
            if brk:
                break
            stdout.write('\rloading ' + c)
            stdout.flush()
            sleep(0.1)
        stdout.write('\rDone!     ')

def bit_lenght(a):
    s = bin(a).lstrip('-0b')
    return str(len(s))
