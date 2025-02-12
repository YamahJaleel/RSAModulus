import random
import sympy
import mysql.connector

mydb = mysql.connector.connect(
    host="",
    user="",
    password="",
    database=""
)

mycursor = mydb.cursor()

mycursor.execute("DESCRIBE users")
for row in mycursor.fetchall():
    print(row)

#Generates a random prime number.
def generate_prime():
    return sympy.randprime(2, 99)

#Generates the public key (e, n) such that (1 < e < phi_n).
def generate_public_key(p, q):
    
    n = p * q   # Compute n
    phi_n = (p - 1) * (q - 1)  # Compute φ(n)
    while True:
        e = random.randint(2, phi_n - 1)  # Ensure e is within a valid range
        if sympy.gcd(e, phi_n) == 1:  # Ensure e is coprime to φ(n)
            return e, n 

#Computes the private key exponent d as the modular inverse of e modulo φ(n).
def generate_private_key(e, p, q):
    phi_n = (p - 1) * (q - 1)  # Compute φ(n)
    d = sympy.mod_inverse(e, phi_n)  # Find d such that (d * e) % φ(n) == 1
    return d

def encrypt_message(message, e, n):
    """
    The sender encrypts their message by raising it to the power of e (from the public key), 
    and then taking the modulus of n (also from the public key). This results in the ciphertext.
    
    Encryption formula:
        C = (M^e) % n
    where:
        - M is the numerical representation of the message character
        - e is the public exponent
        - n is the modulus
    """
    encrypted_message = [pow(ord(char), e, n) for char in message]  # Encrypt each character
    return encrypted_message

def decrypt_message(encrypted_message, d, n):
    """
    The receiver decrypts the ciphertext by raising it to the power of d (from the private key),
    and then taking the modulus of n. This reverses the encryption process.
    
    Decryption formula:
        M = (C^d) % n
    where:
        - C is the encrypted numerical value
        - d is the private exponent
        - n is the modulus
    """
    decrypted_message = ''.join(chr(pow(char, d, n)) for char in encrypted_message)  # Decrypt each character
    return decrypted_message

def test():
    # Generate two large prime numbers
    p = generate_prime()
    q = generate_prime()
    e, n = generate_public_key(p, q)  # Generate public key exponent
    d = generate_private_key(e, p, q)  # Generate private key exponent

    print("\n")
    print(f"Generated primes: p = {p}, q = {q}")
    print(f"Public Key: (e={e}, n={n})")
    print(f"Private Key: (d={d}, n={n})")

    print("\n")
    input_message = input("Provide a message for encryption -> ")
    print("\nOriginal Message:", input_message)

    # Encrypt the message
    encrypted_text = encrypt_message(input_message, e, n)
    print("\nEncrypted Message:", encrypted_text)

    # Decrypt the message
    decrypted_text = decrypt_message(encrypted_text, d, n)
    print("\nDecrypted Message:", decrypted_text)
    print("\n")




#if __name__ == "__main__":
    #test()