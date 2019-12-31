# RSA Asymmetric Cipher
## Python Implementation

This is a basic implementation of an asymmetric cipher, able to generate keys of a provided lenght, as well as encrypt and 
decrypt messages. 

Note: While it is mathematically impossible to derive any of the keys without the other, the nature of pseudo-random number generation makes this unsafe for real world applications. 

## Key generator     
```
	gen
		 -l --lenght     - specify keylen, if none default of 1024 bits is used
		 -o --output     - output path
		 --force         - overwrite existing key file
		 --print         - print keys to screen
```
## Encrypter
```
	en
		--publickey	 - specify path to public key
		-f, --file	 - specify path to file
		-o, --output	 - specify output path
```
## Decrypter
```
	de
		--privatekey	 - specify path to private key
		-f, --file	 - specify path to file
		-o, --output	 - specify output path
```
## Usage examples
```
python pkc.py gen -l 64 -o /home/user/documents/
python pkc.py en --publickey /root/pub_key.dat -f myfile.txt -o /home/user/Documents/my_encrypted_file.txt
python pkc.py de -f my_encrypted_file --privatekey priv_key.dat --output 
/home/user/Documents/my_decrypted_file.txt
``` 
