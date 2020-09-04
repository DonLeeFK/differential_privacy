"""
"""
import random, sys 
from math import floor
from time import time

from gmpy2 import mpz, powmod, invert, is_prime, random_state, mpz_urandomb, rint_round, log2, gcd, mul, div, sub, mpz_random

rand=random_state(random.randrange(sys.maxsize))

class PrivateKey(object):
    def __init__(self, p, q, n):
        if p==q:
            self.l = p * (p-1)
        else:
            self.l = (p-1) * (q-1)
        try:
            self.m = invert(self.l, n)
        except ZeroDivisionError as e:
            print(e)
            exit()

class PublicKey(object):
    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1
        self.bits=mpz(rint_round(log2(self.n)))

def generate_prime(bits):    
    """Will generate an integer of b bits that is prime using the gmpy2 library  """    
    while True:
        possible =  mpz(2)**(bits-1) + mpz_urandomb(rand, bits-1 )
        if is_prime(possible):
            return possible

def generate_random(bits):
    possible = mpz(2)**(bits-1)+mpz_urandomb(rand,bits-1)
    return possible

def generate_keypair(bits):
    """ Will generate a pair of paillier keys bits>5"""
    p = generate_prime(bits // 2)
    #print(p)
    q = generate_prime(bits // 2)
    #print(q)
    n = p * q
    return PrivateKey(p, q, n), PublicKey(n)

def enc(pub, plain):#(public key, plaintext) #to do
    r = random.randint(0,int(pub.n))
    while gcd(r, pub.n) != 1:
        r = random.randint(0,int(pub.n))
    if isinstance(plain, list):
        cipher = [powmod(pub.g,p,pub.n_sq)*powmod(r,pub.n,pub.n_sq)%pub.n_sq for p in plain]
    else:
        cipher = powmod(pub.g,plain,pub.n_sq)*powmod(r,pub.n,pub.n_sq)%pub.n_sq
    return cipher

def dec(priv, pub, cipher): #(private key, public key, cipher) #to do
    if isinstance(cipher, list):
        plain = [(((powmod(c,priv.l,pub.n_sq)-1)//pub.n)*priv.m)%pub.n for c in cipher]
    else:
        plain = (((powmod(cipher,priv.l,pub.n_sq)-1)//pub.n)*priv.m)%pub.n
    return plain

def enc_add(pub, m1, m2): #to do
    """Add one encrypted integer to another"""
    m = (m1*m2)%pub.n_sq
    return m

def enc_add_const(pub, m1, c): #to do
    """Add constant n to an encrypted integer"""
    m = (m1*pub.g**c)%pub.n_sq
    return m

def enc_mul_const(pub, m1, c): #to do
    """Multiplies an encrypted integer by a constant"""
    m = (m1**c)%pub.n_sq
    return m

if __name__ == '__main__':
    priv, pub = generate_keypair(1024)
    message = 'The following program uses list comprehension to convert a string to a list of ASCII values:'
    plain = [mpz(ord(c)) for c in message]
    #print(plain)
    ciphertext = enc(pub,plain)
    print(ciphertext)
    print(''.join([chr(ascii) for ascii in dec(priv,pub,ciphertext)]))
    #print(gcd(1024,99))
    m1 = 114
    m2 = 514
    c1 = enc(pub, m1)
    c2 = enc(pub, m2)
    '''
    print(dec(priv,pub,enc_add(pub,c1,c2)))
    print(dec(priv,pub,enc_add_const(pub,c1,2)))
    print(dec(priv,pub,enc_mul_const(pub,c1,2)))
    '''
    time_count = 0
    for i in range(1000):
        bits = random.randint(10,1000)
        num1 = generate_random(bits)
        bits = random.randint(10,1000)
        num2 = generate_random(bits)
        correct = num1+num2
        time_start = time()
        test = dec(priv, pub, enc_add(pub,enc(pub,num1),enc(pub,num2)))
        time_end = time()
        if correct == test:
            print('{} + {} = {}'.format(num1,num2,correct), end=' ')
            print('time%f'%(time_end-time_start))
            time_count += (time_end-time_start)
        else:
            print('WRONG!')

    print('time average: %f'%(time_count/1000))


