import math, random

# return true if num is prime
def isPrimeModTest(num):
    if num < 2:
        return False
    
    for i in range(2, int(math.sqrt(num)) + 1):
        if num % i == 0:
            return False
    return True


def primeSieve(sieveSize):
    # calculate sieve and return list
    sieve = [True] * sieveSize
    sieve[0] = False
    sieve[1] = False

    for i in range(2, int(math.sqrt(sieveSize)) + 1):
        pointer = i * 2
        while pointer < sieveSize:
            sieve[pointer] = False
            pointer += 1

    primes = []
    for i in range(sieveSize):
        if sieve[i] == True:
            primes.append(i)
    return primes

def rabinMiller(num):
    if num % 2 == 0 or num < 2:
        return False
    if num == 3:
        return True
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True

LOW_PRIMES = primeSieve(100)

def isPrime(num):
    if (num < 2):
        return False
    for prime in LOW_PRIMES:
        if (num % prime == 0):
            return False
    return rabinMiller(num)

def genPrime(keysize=1024):
    while True:
        num = random.randrange(2**(keysize-1),2**(keysize))
        if isPrime(num):
            return num

def gcd(a, b):
    while a != 0:
            a, b = b % a, a
    return b

def modInverse(a, m):
    if gcd(a, m) != 1:
        return None
    u1,u2,u3 = 1,0,a
    v1,v2,v3 = 0,1,m
    while v3 != 0:
        q = u3 // v3
        v1,v2,v3,u1,u2,u3 = (u1 - q * v2),(u3 - q * v3), v1,v2,v3
    return u1 % m