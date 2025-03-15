import os
import hashlib
import base64

def generate_salt(length=16):
    return os.urandom(length)

def hash_data(data, salt):
    hasher = hashlib.pbkdf2_hmac('sha256', data.encode(), salt, 100000)
    return base64.b64encode(hasher).decode()

def verify_hash(data, salt, hashed_data):
    new_hash = hash_data(data, salt)
    return new_hash == hashed_data

def encode_base64(data):
    return base64.b64encode(data).decode()

def decode_base64(data):
    return base64.b64decode(data.encode())

def read_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_file(file_path, data):
    with open(file_path, 'w') as file:
        file.write(data)