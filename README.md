<p align="center">
  <img src="animation.gif" alt="Project Animation" width="700px">
</p>

# 🔐 RSA Modulus Encryption

Welcome to **RSA Modulus Encryption**, a simple Python-based RSA encryption and decryption program. This project demonstrates how to securely encrypt and decrypt messages using the **RSA algorithm**, one of the most widely used encryption techniques.

---

## 📌 Features

✅ Generates **random prime numbers** for encryption keys.\
✅ Creates **public and private keys** dynamically.\
✅ **Encrypts messages** using modular exponentiation.\
✅ **Decrypts messages** back to the original text.\
✅ Simple and easy-to-understand implementation.

---

## 🚀 Getting Started

### **1️⃣ Clone the Repository**

```bash
git clone https://github.com/YamahJaleel/RSAModulus.git
cd RSAModulus
```

### **2️⃣ Install Dependencies**

Make sure you have Python **3.7+** installed. Install required libraries:

```bash
pip install sympy
```

### **3️⃣ Run the Encryption Program**

```bash
python main.py
```

---

## 🔑 How It Works

### **1. Key Generation**

- Two **random prime numbers** (`p` and `q`) are generated.
- Compute `n = p * q` and Euler's totient `φ(n) = (p-1) * (q-1)`.
- Choose an encryption exponent `e`, ensuring `gcd(e, φ(n)) = 1`.
- Compute `d`, the **modular inverse** of `e` (this forms the private key).

### **2. Encryption Process**

Each character in the message is encrypted using:

```
C = (M^e) % n
```

Where:

- `C` = Ciphertext
- `M` = ASCII representation of the message character
- `e, n` = Public key components

### **3. Decryption Process**

Each character in the encrypted message is decrypted using:

```
M = (C^d) % n
```

Where:

- `M` = Original character
- `C` = Encrypted character
- `d, n` = Private key components

---

## 📖 Example Usage

### **Sample Run**

```bash
Provide a message for encryption -> Hello RSA!
```

#### **Output:**

```bash
Generated primes: p = 61, q = 53
Public Key: (e=17, n=3233)
Private Key: (d=2753, n=3233)

Original Message: Hello RSA!
Encrypted Message: [encrypted numbers]
Decrypted Message: Hello RSA!
```

---

## 🛠️ Functions Explained

| Function                                   | Description                      |
| ------------------------------------------ | -------------------------------- |
| `generate_prime()`                         | Generates a random prime number. |
| `generate_public_key(p, q)`                | Generates public key `(e, n)`.   |
| `generate_private_key(e, p, q)`            | Computes the private key `d`.    |
| `encrypt_message(message, e, n)`           | Encrypts a given message.        |
| `decrypt_message(encrypted_message, d, n)` | Decrypts an encrypted message.   |

---

## 🔒 Security Considerations

⚠ **This implementation is for educational purposes only.**

- Uses **small prime numbers** (not secure for real-world encryption).
- Does not implement **padding** (e.g., PKCS#1).
- Recommended for **learning RSA**, not production use.

---

## 📜 License

This project is licensed under the **MIT License**. Feel free to use and modify it!
