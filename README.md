# Simple Crypto Library

This project offers a handful of basic cryptographic routines implemented in
pure Python.  It is intended for educational purposes and for small-scale
applications that require lightweight encryption or hashing without bringing in
heavy external dependencies.

> **Note:** These algorithms are *not* suitable for securing sensitive data in
> production systems.  They are included here to demonstrate core concepts of
> cryptography and are best used for learning or for protecting low-risk
information.

## Features

- **Caesar cipher** (shift cipher) with arbitrary rotation and support for
  uppercase/lowercase letters.
- **XOR cipher** using a repeating key to encrypt and decrypt binary data.
- **Hashing utilities** for computing SHA-256 and MD5 digests.

## Installation

This project has no external dependencies beyond Python 3.8+.  Simply clone
the repository and import the `simple_crypto` module into your projects.

## Usage

Below are some examples that illustrate how to use the functions provided by
`simple_crypto.py`.

### Caesar Cipher

```python
from simple_crypto import caesar_encrypt, caesar_decrypt

plaintext = "Hello, World!"
encrypted = caesar_encrypt(plaintext, shift=5)
print(encrypted)  # Mjqqt, Btwqi!
decrypted = caesar_decrypt(encrypted, shift=5)
print(decrypted)  # Hello, World!
```

### XOR Cipher

```python
from simple_crypto import xor_cipher

data = b"Secret data!"
key = b"key"
encrypted = xor_cipher(data, key)
print(encrypted)  # returns a bytes object
decrypted = xor_cipher(encrypted, key)
print(decrypted.decode())  # Secret data!
```

### Hashing

```python
from simple_crypto import sha256_digest, md5_digest

print(sha256_digest("hello"))
print(md5_digest("hello"))
```

## License

This library is distributed under the MIT License.  See the `LICENSE`
file for details.
