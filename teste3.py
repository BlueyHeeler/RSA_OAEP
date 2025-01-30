import hashlib              # biblioteca para hash
import random               # biblioteca para números aleatórios
from math import gcd        # biblioteca para cálculo de MDC
import base64               # biblioteca para codificação e decodificação de base64

def decompondo(n):
    """
    Decompõe n-1 como 2^e * m, onde n é ímpar.
    Args:
        n: número para decompor
    Returns:
        int: expoente
        int: número
    """
    e = 0
    m = n - 1
    while m % 2 == 0:
        m //= 2        
        e += 1
    return e, m

def miller_rabin(n, rodadas=10):
    """
    Miller-Rabin primality test
    Args:
        n: numero para ser testado
        rodadas: quantidade de rodadas a serem feitas
    Returns:
        bool: True se é primo, False se não é primo
    """
    if n <= 1 or n == 4:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    expo_k, m = decompondo(n)  #exponte K e m tal que n - 1 = 2^k * m
    for _ in range(rodadas):
        a = random.randrange(2, n - 2) # pega um numero aleatorio entre 2 e n-2
        """ x = a^m mod n """
        x = pow(a, m, n) 
        if x == 1 or x == n-1: # se x for 1 ou n-1, então n é primo
            continue
        else:
            teste = False
            for _ in range(expo_k - 1): # para i de 0 até k-1
                """ x = x^2 mod n """ 
                x = pow(x, 2, n)
                if x == n-1:
                    teste = True
                    break
            if(teste):
                continue
            else:
                return False
    return True

"""
count = 0
for i in range(2, 7920):
    if(miller_rabin(i)):
        count += 1
print(count)
"""

def mgf1(seed: int, length: int, hash_func=hashlib.sha1) -> bytes: #máscara de geração de função
    if length > (hash_func().digest_size * (2**32)): #tamanho da máscara 
        raise ValueError("mask too long")
    # Converte o tamanho de bits para bytes
    byte_length = (length + 7) // 8
    # Converte a seed para um tamanho fixo de bytes
    seed_bytes = seed.to_bytes((seed.bit_length() + 7) // 8, byteorder='big')
    T = b""
    counter = 0
    while len(T) < byte_length: # enquanto o tamanho de T for menor que o tamanho de bytes
        C = counter.to_bytes(4, byteorder='big')
        T += hash_func(seed_bytes + C).digest()
        counter += 1
    return T[:byte_length]

def shift_left(shift_values, n): #deslocamento para a esquerda
    """
    Shift Left
    Args:
        shift_values: quantidade de shift
        n: número para ser shiftado
    Returns:
        int: número shiftado
    """
    return n << shift_values

def shift_right(shift_values, n): #deslocamento para a direita
    """
    Shift Right
    Args:
        shift_values: quantidade de shift
        n: número para ser shiftado
    Returns:
        int: número shiftado
    """
    return n >> shift_values

def msb(n): #bit mais significativo
    """
    Most Significant Bit
    Args:
        n: número para ser calculado o MSB
    Returns:
        int: MSB
    """
    msb = 0
    while n > 0:
        n >>= 1
        msb += 1
    return msb

def number_of_bits(n): #calcula o número de bits de um certo número
    """
    Number of Bits
    Args:
        n: número para ser calculado a quantidade de bits
    Returns:
        int: quantidade de bits
    """
    temp = n
    count = 0
    while(temp != 0):
        temp = shift_right(1, temp)
        count += 1
    return count

def DB(pHash, mensagem): #faz a concatenação de pHash e mensagem
    """
    DB
    Obs:
        padding mínimo de 8 bits
    Args:
        pHash: pHash
        mensagem: mensagem
    Returns:
        int: DB com padding
    """
    pHash = shift_left(1536 , pHash)
    pHash = pHash | shift_left(number_of_bits(mensagem), 1)
    return (pHash | mensagem)

pHash = hashlib.sha3_256().digest()
pHash = int.from_bytes(pHash, byteorder='big')
mensagem = 15
print(bin(DB(pHash, mensagem)))