import random
import sympy
import logging

def generate_prime():
    return sympy.randprime(2, 99)

def generate_public_key(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while True:
        e = random.randint(2, phi_n - 1)
        if sympy.gcd(e, phi_n) == 1:
            return e, n 

def generate_private_key(e, p, q):
    phi_n = (p - 1) * (q - 1)
    d = sympy.mod_inverse(e, phi_n)
    return d

def encrypt_message(message, e, n):
    try:
        encrypted_message = [pow(ord(char), e, n) for char in message]
        logging.info("Message encrypted.")
        return encrypted_message
    except Exception as e:
        logging.error("Encryption error: %s", e)
        print("Encryption failed.")
        return None

def decrypt_message(encrypted_message, d, n):
    try:
        decrypted_message = ''.join(chr(pow(char, d, n)) for char in encrypted_message)
        logging.info("Message decrypted.")
        return decrypted_message
    except Exception as e:
        logging.error("Decryption error: %s", e)
        print("Decryption failed.")
        return None
