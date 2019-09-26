import time, threading, os
from keygen import KeyContainer, _KeyGenerator
from numbers import Integral
from itertools import cycle
from sys import stdout, platform
from ctypes import pythonapi, py_object

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


class Helper_Thread(threading.Thread):

    def __init__(self,name,msg,inter=0.065):
        threading.Thread.__init__(self)
        self.name = name
        self.msg = msg
        self.inter = inter

    def __repr__(self):
        return '{self.__class__.__name__}({self.name}, {self.msg}, {self.inter})'.format(self=self)
    
    # load specified animation set
    def run(self):
        try:
            while True:
                __class__.load_animation(self.msg, self.inter)
        finally:
            __class__.load_animation(self.msg,self.inter,run=False)

    # get id for each tread
    def get_id(self): 
        for id, thread in threading._active.items(): 
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
            time.sleep(inter)   

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
      

