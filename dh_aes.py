from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

P = 0xFFFFFFFB
G = 5

def compute_shared_key():
    shared_secret = pow(G, 12345 * 67890, P)
    key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]
    return key

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return cipher.iv, ciphertext

def aes_decrypt(ciphertext, iv, key):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()
