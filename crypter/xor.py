from utils import bitwise


def encrypt(plain: bytes, key: bytes):
    key_length = len(key)
    encryption_key = key
    if key_length < len(plain):
        encryption_key = key * (len(plain) // key_length + 1)
        encryption_key = encryption_key[:len(plain)]

    if key_length > len(plain):
        encryption_key = key[:len(plain)]

    return bitwise.xor(plain, encryption_key)


def decrypt(cipher: bytes, key: bytes):
    return encrypt(cipher, key)
