from .funcoes import *
import hashlib
import random
from math import gcd
import base64

def decompondo(n):
    """Decompõe n-1 como 2^k * m, onde m é ímpar."""
    k = 0
    m = n - 1
    while m % 2 == 0:  # Enquanto m for divisível por 2
        m //= 2        # Divisão inteira por 2
        k += 1
    return k, m

def miller_rabin(n, k=10):
    """Teste de primalidade de Miller-Rabin com k iterações."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Decompor n-1 como 2^k * m
    k, m = decompondo(n)

    def check(a, m, n, k):
        b = pow(a, m, n)  # b = a^m mod n
        if b == 1 or b == n - 1:
            return True
        for _ in range(k - 1):
            b = pow(b, 2, n)  # b = b^2 mod n
            if b == n - 1:
                return True
        return False

    for _ in range(k):
        a = random.randint(2, n - 2)
        if not check(a, m, n, k):
            return False

    return True

def mgf1(seed: int, length: int, hash_func=hashlib.sha1) -> bytes:

    if length > (hash_func().digest_size * (2**32)):
        raise ValueError("mask too long")

    byte_length = (length + 7) // 8
    seed_bytes = seed.to_bytes((seed.bit_length() + 7) // 8, byteorder='big')

    T = b""
    counter = 0

    while len(T) < byte_length:
        C = counter.to_bytes(4, byteorder='big')
        T += hash_func(seed_bytes + C).digest()
        counter += 1

    return T[:byte_length]

def shift_left(shift_values, n):
    n = n << shift_values
    return n

def shift_right(shift_values, n):
    n = n >> shift_values
    return n

def msb(n):
    msb = 0
    while n > 0:
        n >>= 1
        msb += 1
    return msb

def number_of_bits(n):
    temp = n
    count = 0
    while(temp != 0):
        temp = shift_right(1, temp)
        count += 1
    return count

def DB(pHash, mensagem):
    """padding mínimo de 8 bits"""
    pHash = shift_left(1536 , pHash)
    pHash = pHash | shift_left(number_of_bits(mensagem), 1)
    return (pHash | mensagem)

def prime_numbers():
    n = 1 << 1024
    contador = 0
    par_de_numeros_primos = []
    while True:
        if miller_rabin(n):
            par_de_numeros_primos.append(n)
            contador += 1
        if contador == 2:
            break
        n += 1
    return par_de_numeros_primos

def enc_oaep(mensagem):
    seed = random.getrandbits(256).to_bytes(32, byteorder="big")
    seed = int.from_bytes(seed, byteorder='big')

    pHash = hashlib.sha3_256(seed.to_bytes(32, byteorder='big')).digest()
    pHash = int.from_bytes(pHash, byteorder='big')

    maskeDB = DB(pHash, mensagem) ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256))

    maskedSeed = seed ^ int.from_bytes(mgf1(maskeDB, 32, hashlib.sha3_256))

    maskedSeed = shift_left(1792, maskedSeed)

    EM = maskedSeed | maskeDB
    return EM


def dec_oaep(c):
    bit_mask = (1 << 1792) - 1
    maskeDB = c & bit_mask

    maskedSeed = c >> 1792

    seed = maskedSeed ^ int.from_bytes(mgf1(maskeDB, 32, hashlib.sha3_256), byteorder='big')
    db = maskeDB ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256), byteorder='big')

    bit_mask = (1 << 1536) - 1
    m = db & bit_mask

    most_significant_bit = msb(m) - 1

    most_significant_bit = shift_left(most_significant_bit, 1)
    m = m ^ most_significant_bit
    return m

def multiplicative_inverse(a, b):
    if b > a:
        a, b = b, a
    old_a = a
    if gcd(a, b) != 1:
        return None

    if b > a:
        a, b = b, a
    q = a // b
    r = a % b
    t1 = 0
    t2 = 1
    t = t1 - t2 * q
    while b != 0:
        a, b = b, r
        if b == 0:
            t1 = t2
            if t1 < 0:
                t1 += old_a
            return t1
        q = a // b
        r = a % b
        t1, t2 = t2, t
        t = t1 - t2 * q

def enc_rsa(n, e, m):
    c = pow(m, e, n)
    return c, n

def dec_rsa(p, q, e, c):
    n = p * q
    phi = (p - 1) * (q - 1)
    d = multiplicative_inverse(phi, e)
    m = pow(c, d, n)
    return m
