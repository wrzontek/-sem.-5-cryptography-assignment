import json
import os
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA


# Communication utils

def read_until(s, suffix):
    res = b''
    while not res.endswith(suffix):
        # quite slow, but should be enough for us
        d = s.recv(1)
        if len(d) == 0:
            raise EOFError()
        res += d
    return res

# symmetric cryptography

def xor(a, b):
    return bytes([ac ^ bc for ac, bc in zip(a, b)])


def aes_encrypt(key, text):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return cipher.nonce.hex() + ':' + ciphertext.hex() + ':' + tag.hex()

def aes_encrypt_nonce(key, text, nonce):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(text)
    return cipher.nonce.hex() + ':' + ciphertext.hex() + ':' + tag.hex()

# asymmetric cryptography
def aes_decrypt(key, text, nonce):
    d_cipher = AES.new(key, AES.MODE_GCM, nonce)
    return d_cipher.decrypt(text)

def rsa_encrypt(key, message):
    key = RSA.import_key(key)
    return key._encrypt(message)


def rsa_decrypt(key, message):
    key = RSA.import_key(key)
    return key._decrypt(message)


def convert_to_public(key):
    key = RSA.import_key(key)
    return key.publickey().export_key('PEM').decode()
