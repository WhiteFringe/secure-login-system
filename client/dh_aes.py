import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

P = 0xFFFFFFFB
G = 5

def generate_dh_keys():
    private = int.from_bytes(os.urandom(16), 'big')
    public = pow(G, private, P)
    return private, public

def compute_shared_key(peer_public, private):
    shared_secret = pow(peer_public, private, P)
    return hashlib.sha256(str(shared_secret).encode()).digest()[:16]

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv + ciphertext

def aes_decrypt(data, key):
    if not data or len(data) < 16:
        raise ValueError("Invalid data: too short for AES decryption")
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        return unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8', errors='ignore')
    except ValueError as e:
        raise ValueError(f"Decryption failed: {e}")
