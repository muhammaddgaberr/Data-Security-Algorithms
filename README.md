# Data Security Algorithms – C#

Implementation of several classical and modern cryptographic algorithms in C#.

The main goal of this project was to implement the **core logic of encryption, decryption, and key analysis algorithms** as part of a Data Security course assignment.

## Technologies

- C#
- .NET
- Cryptography Algorithms
- Problem Solving

## Implemented Algorithms

### Classical Ciphers
- Caesar Cipher
- PlayFair Cipher
- Hill Cipher
- Columnar Transposition Cipher
- Rail Fence Cipher
- Monoalphabetic Cipher
- Repeating Key Vigenère

### Modern Cryptographic Algorithms
- DES
- Triple DES
- AES
- RC4
- RSA
- Diffie-Hellman
- ElGamal

## Features

Each algorithm includes implementations for:

- `Encrypt(plaintext, key)`
  - Produces the encrypted ciphertext.

- `Decrypt(ciphertext, key)`
  - Recovers the original plaintext.

Some algorithms also include:

- `Analyze(plaintext, ciphertext)`
  - Attempts to determine the encryption key.

## Testing

Unit tests were provided with the assignment to validate the correctness of each algorithm implementation.

These tests ensure that the implemented encryption, decryption, and analysis functions produce the expected results.

## Learning Focus

The primary focus of this project was:

- Implementing cryptographic algorithms
- Writing the logical implementation of encryption and decryption
- Solving algorithmic problems related to cryptography

### Unit Tests
![Tests](images/tests.png)
