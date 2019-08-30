import math, random

# calculate sieve and return list of primes
def primeSieve(sieveSize):
    sieve = [True] * sieveSize
    sieve[0] = False
    sieve[1] = False

    #n > 2 < n^sieveSize + 1
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

# Rabin Miller primality test Python implementation by Al Sweigart
def rabinMiller(n):
    if n % 2 == 0 or n < 2:
        return False
    if n == 3:
        return True
    s = n - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1
    for trials in range(5):
        a = random.randrange(2, n - 1)
        v = pow(a, s, n)
        if v != 1:
            i = 0
            while v != (n - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % n
    return True

LOW_PRIMES = primeSieve(100)

# func to check if n is prime using lowest 100 prime n
# resorts to rabinMiller() if not found
# faster method than trialDiv() for large ints
def isPrime(n):
    if (n < 2):
        return False
    for prime in LOW_PRIMES:
        if (n % prime == 0):
            return False
    return rabinMiller(n)

# generate primenumber with specified size
# generated number will be s bits in size
def genPrime(s=1024):
    while True:
        # generate random number in range of 2^keysize -1 and 2^keysize
        n = random.randrange(2**(s-1), 2**(s))
        if isPrime(n):
            return n

# return true if n is prime using trial division algorithm
def trialDiv(n):
    # 1 is not prime
    if n < 2:
        return False
    # for every n > 2 < n^2 + 1 
    for i in range(2, int(math.sqrt(n)) + 1):
        #if modulo is 0 n is not prime
        if n % i == 0:
            return False
    # otherwise n is prime
    return True

# mod inverse Python implementation by Al Sweigart
def modInverse(a, m):
    if math.gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1 ,v2, v3
    return u1 % m