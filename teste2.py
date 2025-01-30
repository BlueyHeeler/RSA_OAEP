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

def miller_rabin(n, rodadas=5):
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
    for i in range(rodadas):
        a = random.randrange(2, n - 2) # pega um numero aleatorio entre 2 e n-2
        """ x = a^m mod n """
        x = pow(a, m, n) 
        eh_primo = False
        if x == 1 or x == n-1: # se x for 1 ou n-1, então n é primo
            eh_primo = True
        else:
            for i in range(expo_k - 1): # para i de 0 até k-1
                """ x = x^2 mod n """ 
                x = pow(x, 2, n)
                if x == n-1:
                    eh_primo = True
                    break
        if eh_primo:
            return True
    return False

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

def prime_numbers(): #descobre os números primos usando a função de Miller-Rabin
    """
    Descobrindo os números primos
    Args: none
    Returns:
        list: lista com os números primos
    """
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

""""
Descobrindo o pHash e a seed 


seed = random.getrandbits(256).to_bytes(32, byteorder="big")
seed = int.from_bytes(seed, byteorder='big')

pHash = hashlib.sha3_256(seed.to_bytes(32, byteorder='big')).digest()
pHash = int.from_bytes(pHash, byteorder='big')
mensagem = 101

print("DB:", bin(DB(pHash, mensagem)))
print("Number of bits: ", number_of_bits(DB(pHash, mensagem)))

maskeDB = DB(pHash, mensagem) ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256))

maskedSeed = seed ^ int.from_bytes(mgf1(maskeDB, 32, hashlib.sha3_256))

maskedSeed = shift_left(1792, maskedSeed)

EM = maskedSeed | maskeDB

#================================================================================================#
bit_mask = pow(2, 257) - 1
bit_mask = shift_left(1792, bit_mask)
maskedSeed = EM & bit_mask
maskedSeed = shift_right(1792, maskedSeed)

bit_mask = pow(2, 1793) - 1
maskeDB = EM & bit_mask

seed = maskedSeed ^ int.from_bytes(mgf1(maskeDB, 32, hashlib.sha3_256), byteorder='big')
db = maskeDB ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256), byteorder='big')

print("DB: ", bin(db))
print("Number of bits: ", number_of_bits(db))

"""

def enc_oaep(mensagem): #encriptação OAEP
    """
    Encapsulamento OAEP
    Args:
        mensagem: mensagem
    Returns:
        int: EM
    """
    seed = random.getrandbits(256).to_bytes(32, byteorder="big")                                # gera uma seed aleatória
    seed = int.from_bytes(seed, byteorder='big')                                                # converte a seed para int
    pHash = hashlib.sha3_256(seed.to_bytes(32, byteorder='big')).digest()                       # hash da seed
    pHash = int.from_bytes(pHash, byteorder='big')                                              # converte o hash da seed para int
    mascaraDB = DB(pHash, mensagem) ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256))        # faz a concatenação de pHash e mensagem
    mascaraSeed = seed ^ int.from_bytes(mgf1(mascaraDB, 32, hashlib.sha3_256))                  # faz a máscara da seed
    mascaraSeed = shift_left(1792, mascaraSeed)                                                 # desloca a seed para a esquerda em 1792 bits
    concat = mascaraSeed | mascaraDB                                                            # concatena a máscara da seed e a máscara da mensagem
    return concat

def dec_oaep(c): #decriptação OAEP
    """
    Decriptando OAEP
    Args:
        c: EM
    Returns:
        int: m
    """
    mascaraBits = (1 << 1792) - 1                                                                           # máscara de bits
    mascaraDB = c & mascaraBits                                                                             # máscara de DB
    mascaraSeed = c >> 1792                                                                                 # mascara da seed
    seed = mascaraSeed ^ int.from_bytes(mgf1(mascaraDB, 32, hashlib.sha3_256), byteorder='big')
    db = mascaraDB ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256), byteorder='big')                
    mascaraBits = (1 << 1536) - 1
    m = db & mascaraBits
    MSBit = msb(m) - 1
    MSBit = shift_left(MSBit, 1)
    m = m ^ MSBit
    return m
    
def multiplicative_inverse(a, b): # calcula o inverso multiplicativo usando o Algoritmo extendido de Euclides
    """
    Inverso multiplicativo
    Obs
        a > b
        a * t1 ≅ 1 mod b
    Args:
        a: número
        b: número
    Returns:
        int: inverso multiplicativo
    """
    if b > a:
        a, b = b, a
    old_a = a                                       
    if gcd(a, b) != 1:                              
        return None
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

def base64_encode(mensagem): #codificação usando a base64
    """
    Base64 Encode
    Args:
        mensagem: mensagem
    Returns:
        bytes: mensagem codificada
    """
    mensagem = mensagem.encode('utf-8')
    mensagem = base64.b64encode(mensagem)
    return mensagem

def base64_decode(mensagem_encriptada): #decodificação usando a base64
    """
    Base64 Decode
    Args:
        mensagem_encriptada: int mensagem encriptada
    Returns:
        str: mensagem decodificada
    """
    mensagem_encriptada = mensagem_encriptada.to_bytes((mensagem_encriptada.bit_length() + 7) // 8, byteorder='big')
    mensagem_encriptada = base64.b64decode(mensagem_encriptada).decode('utf-8')
    return mensagem_encriptada

def enc_rsa(n, e, m): #encriptação RSA
    """
    RSA Encryption
    Args:
        n: produto dos primos n
        e: chave públic e
        m: mensagem
    Returns:
        int: c
        int: n
    """
    c = pow(m, e, n)
    return c, n

def dec_rsa(p, q, e, c): #decriptação RSA
    """
    RSA Decryption
    Args:
        p: primo p
        q: primo q
        e: chave pública e
        c: mensagem criptografada
    Returns:
        int: mensagem descriptografada m
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = multiplicative_inverse(phi, e)
    m = pow(c, d, n)
    return m

def assinatura_com_rsa(message, key, n): #assinatura com RSA
    message = base64_encode(message)
    message = int.from_bytes(message, byteorder='big')
    hash_message = hashlib.sha3_256(message.to_bytes(32, byteorder='big')).digest()
    hash_message = int.from_bytes(hash_message, byteorder='big')
    encrypted_hash = enc_rsa(n, key, hash_message)[0]
    return message, encrypted_hash

def verificar_assinatura_com_rsa(message, enc_hash, e, n):
    decrypted_hash = enc_rsa(n, e, enc_hash)
    hash_message = hashlib.sha3_256(message.to_bytes(32, byteorder='big')).digest()
    hash_message = int.from_bytes(hash_message, byteorder='big')
    return decrypted_hash[0] == hash_message

"""========================================================================================================"""
# Teste de execução do programa

lista = prime_numbers()
p = lista[0]
q = lista[1]
n = p * q
phi = (p - 1) * (q - 1)
e = 65537
message = "Bluey Heeler"

print("Texto original:", message)
print("================================================================================")
message = base64_encode(message)
print("Message com BASE64:", message)
print("================================================================================")
message = enc_oaep(int.from_bytes(message, byteorder='big'))
print("Message com OAEP:", message)
print("================================================================================")
enc_message = enc_rsa(p * q, e, message)[0]
print("Message encriptada com RSA:", enc_message)
print("================================================================================")
dec_message = dec_rsa(p, q, e, enc_message)
print("Message descriptografada com RSA:", dec_message)
print("====================================================================================")
dec_message = dec_oaep(dec_message)
print("Message descriptografada com OAEP:", dec_message)
print("================================================================================")
dec_message = base64_decode(dec_message)
print("Message descriptografada com BASE64:", dec_message)

d = multiplicative_inverse(e, phi)
message = "Bluey Heeler"
c = (assinatura_com_rsa(message, d, n))
verificar_assinatura_com_rsa(c[0], c[1], e, n)