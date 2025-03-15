from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

def des3_encrypt(data, key):
    cipher = DES3.new(key, DES3.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(data, DES3.block_size))

def des3_decrypt(encrypted_data, key):
    iv = encrypted_data[:8]
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(encrypted_data[8:]), DES3.block_size)