def xor_encrypt(data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_decrypt(encrypted_data, key):
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(encrypted_data)])