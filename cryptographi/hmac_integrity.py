from cryptography.hazmat.primitives import hashes, hmac

def generate_hmac(data, key):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()

def verify_integrity(data, hmac_key, given_hmac):
    h = hmac.HMAC(hmac_key, hashes.SHA256())
    h.update(data)
    try:
        h.verify(given_hmac)
        return True
    except:
        return False