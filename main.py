import hashlib              # biblioteca para hash
import random               # biblioteca para numeros aleatórios
from math import gcd        # biblioteca para calculo de MDC
import base64               # biblioteca para codificaçao e decodificaçao de base64

def decompondo(n):
    """
    Decompoe n-1 como 2^e * m, onde n e ímpar.
    Args:
        n: numero para decompor
    Returns:
        int: expoente
        int: numero
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
        bool: True se e primo, False se nao e primo
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
        if x == 1 or x == n-1: # se x for 1 ou n-1, entao n e primo
            continue
        else:
            teste = False
            for _ in range(expo_k - 1): # para i de 0 ate k-1
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

def mgf1(seed: int, length: int, hash_func=hashlib.sha1) -> bytes: #mascara de geraçao de funçao
    if length > (hash_func().digest_size * (2**32)): #tamanho da mascara 
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
        n: numero para ser shiftado
    Returns:
        int: numero shiftado
    """
    return n << shift_values

def shift_right(shift_values, n): #deslocamento para a direita
    """
    Shift Right
    Args:
        shift_values: quantidade de shift
        n: numero para ser shiftado
    Returns:
        int: numero shiftado
    """
    return n >> shift_values

def msb(n): #bit mais significativo
    """
    Most Significant Bit
    Args:
        n: numero para ser calculado o MSB
    Returns:
        int: MSB
    """
    msb = 0
    while n > 0:
        n >>= 1
        msb += 1
    return msb

def number_of_bits(n): #calcula o numero de bits de um certo numero
    """
    Number of Bits
    Args:
        n: numero para ser calculado a quantidade de bits
    Returns:
        int: quantidade de bits
    """
    temp = n
    count = 0
    while(temp != 0):
        temp = shift_right(1, temp)
        count += 1
    return count

def DB(pHash, mensagem): #faz a concatenaçao de pHash e mensagem
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
    padding = shift_left(number_of_bits(mensagem), 1)
    pHash = pHash | padding
    return (pHash | mensagem)

def prime_numbers(): #descobre os numeros primos usando a funçao de Miller-Rabin
    """
    Descobrindo os numeros primos
    Args: none
    Returns:
        list: lista com os numeros primos
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

def enc_oaep(mensagem): #encriptaçao OAEP
    """
    Encapsulamento OAEP
    Args:
        mensagem: mensagem
    Returns:
        int: EM
    """
    seed = random.getrandbits(256).to_bytes(32, byteorder="big")                                # gera uma seed aleatória
    seed = int.from_bytes(seed, byteorder='big')                                                # converte a seed para int
    pHash = hashlib.sha3_256().digest()                                                         # hash de NULL
    pHash = int.from_bytes(pHash, byteorder='big')                                              # converte o hash da seed para int
    maskedDB = DB(pHash, mensagem) ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256))         # faz a concatenaçao de pHash e mensagem
    maskedSeed = seed ^ int.from_bytes(mgf1(maskedDB, 32, hashlib.sha3_256))                    # faz a mascara da seed
    maskedSeed = shift_left(1792, maskedSeed)                                                   # desloca a seed para a esquerda em 1792 bits
    EM = maskedSeed | maskedDB                                                                  # concatena a mascara da seed e a mascara da mensagem
    return EM

def dec_oaep(c): #decriptaçao OAEP
    """
    Decriptando OAEP
    Args:
        c: EM
    Returns:
        int: m
    """
    bitMask = shift_left(1792, 1) - 1                                                           # bitmask
    maskedDB = c & bitMask                                                                      # retirando o maskedDB do texto cifrado                                 
    maskedSeed = shift_right(1792, c)                                                           # retirando o maskedSeed do texto cifrado
    seed = maskedSeed ^ int.from_bytes(mgf1(maskedDB, 32, hashlib.sha3_256), byteorder='big')   # seed = maskedSeed XOR mgf1(maskedDB)
    db = maskedDB ^ int.from_bytes(mgf1(seed, 1792, hashlib.sha3_256), byteorder='big')         # db = maskedDB XOR mgf1(seed)
    bitMask = shift_left(1536, 1) - 1                                                           # bitmask
    padding_with_message = db & bitMask                                                         # mensagem = db AND bitmask
    MSBit = msb(padding_with_message) - 1                                                       # bit mais significativo
    MSBit = shift_left(MSBit, 1)                                                                # desloca o MSB para a esquerda
    m = padding_with_message ^ MSBit                                                                               # m XOR MSBit
    return m                                                                                    
    
def multiplicative_inverse(a, b): # calcula o inverso multiplicativo usando o Algoritmo extendido de Euclides
    """
    Inverso multiplicativo
    Obs
        a > b
        a x t1 ≅ 1 mod b
    Args:
        a: numero
        b: numero
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

def base64_encode(mensagem): #codificaçao usando a base64
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

def base64_decode(mensagem_encriptada): #decodificaçao usando a base64
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

def enc_rsa(n, e, m): #encriptaçao RSA
    """
    RSA Encryption
    Args:
        n: produto dos primos n
        e: chave public e
        m: mensagem
    Returns:
        int: c
        int: n
    """
    c = pow(m, e, n)
    return c, n

def dec_rsa(p, q, e, c): #decriptaçao RSA
    """
    RSA Decryption
    Args:
        p: primo p
        q: primo q
        e: chave publica e
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
    """
    RSA Signature
    Args:
        message: mensagem
        key: chave privada
        n: produto dos primos
    Returns:
        int: mensagem
        int: hash encriptado
    """
    message = base64_encode(message)
    message = int.from_bytes(message, byteorder='big')
    hash_message = hashlib.sha3_256(message.to_bytes(32, byteorder='big')).digest()
    hash_message = int.from_bytes(hash_message, byteorder='big')
    encrypted_hash = enc_rsa(n, key, hash_message)[0]
    return message, encrypted_hash

def verificar_assinatura_com_rsa(message, enc_hash, e, n):
    """
    RSA Signature Verification
    Args:
        message: mensagem
        enc_hash: hash encriptado
        e: chave publica e
        n: produto dos primos
    Returns:
        bool: True se a assinatura é valida, False se nao é valida
    """
    decrypted_hash = enc_rsa(n, e, enc_hash)
    hash_message = hashlib.sha3_256(message.to_bytes(32, byteorder='big')).digest()
    hash_message = int.from_bytes(hash_message, byteorder='big')
    return decrypted_hash[0] == hash_message

"""========================================================================================================"""
# Teste de execuçao do programa

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
print("================================================================================")
dec_message = dec_oaep(dec_message)
print("Message descriptografada com OAEP:", dec_message)
print("================================================================================")
dec_message = base64_decode(dec_message)
print("Message descriptografada com BASE64:", dec_message)
print("================================================================================")
d = multiplicative_inverse(e, phi)          #Private key
message = "Bluey Heeler"                    
c = (assinatura_com_rsa(message, d, n))
print("Mensagem: ", c[0], "Assinatura: ", c[1])
print("================================================================================")
print(verificar_assinatura_com_rsa(c[0], c[1], e, n))
