"""
simple_crypto.py
-----------------

This module implements several basic cryptographic algorithms for educational
purposes.  The provided functions include a Caesar cipher, a simple XOR
cipher, and hashing utilities using the built-in `hashlib` module.

The Caesar cipher functions operate on strings and shift alphabetical
characters by a fixed amount, wrapping around the alphabet.  The XOR cipher
operates on bytes or strings (internally converted to bytes) and returns a
bytes object representing the encrypted or decrypted data.  The hashing
functions return hexadecimal digests of their input.

While these implementations are functional, they should not be used to secure
sensitive data in production environments.  Cryptography is hard to get
right—use well-tested libraries such as `cryptography` or OpenSSL for any
serious applications.
"""

import hashlib
from typing import Union



def caesar_encrypt(text: str, shift: int) -> str:
    """Encrypt a message using a Caesar cipher.

    Each alphabetical character in the input string will be shifted by `shift`
    positions within the alphabet.  Case is preserved and non-alphabetic
    characters are returned unchanged.

    Args:
        text: The plaintext message to encrypt.
        shift: The number of positions to shift by (can be negative for
            leftward shifts).

    Returns:
        The encrypted message as a string.
    """
    result_chars = []
    for ch in text:
        if 'A' <= ch <= 'Z':
            base = ord('A')
            offset = (ord(ch) - base + shift) % 26
            result_chars.append(chr(base + offset))
        elif 'a' <= ch <= 'z':
            base = ord('a')
            offset = (ord(ch) - base + shift) % 26
            result_chars.append(chr(base + offset))
        else:
            result_chars.append(ch)
    return ''.join(result_chars)


def caesar_decrypt(text: str, shift: int) -> str:
    """Decrypt a message encoded with a Caesar cipher.

    This is the inverse of `caesar_encrypt` and applies the negative shift.
    """
    return caesar_encrypt(text, -shift)


def xor_cipher(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
    """Encrypt or decrypt data using a repeating XOR key.

    Because XOR encryption is symmetric, the same function can be used to both
    encrypt and decrypt.  When the input is a string it will be encoded to
    UTF-8.  The output is always a bytes object.

    Args:
        data: The plaintext/ciphertext to encrypt or decrypt.
        key: The key used to perform the XOR operation.

    Returns:
        A bytes object containing the encrypted or decrypted data.
    """
    if isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = data
    if isinstance(key, str):
        key_bytes = key.encode('utf-8')
    else:
        key_bytes = key

    if not key_bytes:
        raise ValueError("Key must not be empty")

    result = bytearray()
    key_length = len(key_bytes)
    for i, b in enumerate(data_bytes):
        result.append(b ^ key_bytes[i % key_length])
    return bytes(result)


def sha256_digest(text: str) -> str:
    """Return the SHA-256 hex digest of the given text."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def md5_digest(text: str) -> str:
    """Return the MD5 hex digest of the given text."""
    return hashlib.md5(text.encode('utf-8')).hexdigest()


__all__ = [
    'caesar_encrypt',
    'caesar_decrypt',
    'xor_cipher',
    'sha256_digest',
    'md5_digest',
]
