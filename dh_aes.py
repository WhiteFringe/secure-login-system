from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib
import random

# Use large prime & base for DH
P = 0xFFFFFFFB
G = 5

def generate_dh_keys():
    private = random.randint(1000, 10000)
    public = pow(G, private, P)
    return private, public

def compute_shared_key(their_public, my_private):
    shared_secret = pow(their_public, my_private, P)
    key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]  # AES-128
    return key

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv, ciphertext

def aes_decrypt(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()
