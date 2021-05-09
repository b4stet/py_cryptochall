from stats import frequency
from crypter import xor
from utils import encoder


def attack_single_byte(cipher: bytes, lang: str):
    best_plain = b''
    best_score = 0
    best_key = b''

    for key in range(0, 256):
        test_plain = xor.decrypt(cipher, encoder.int_to_bytes(key))
        score = frequency.get_language_score(test_plain, lang=lang)

        if score > best_score:
            best_score = score
            best_plain = test_plain
            best_key = bytes([key])

    return best_key, best_plain, best_score


def attack_repeating_key(cipher: bytes, key_length: int, lang: str):
    # split into block of key length
    blocks = [cipher[i:i+key_length] for i in range(0, len(cipher), key_length)]
    incomplete_block = None
    if len(blocks[-1]) < key_length:
        incomplete_block = blocks.pop()

    # transpose such that each row is a single byte xor cipher
    single_byte_xor_ciphers = []
    for i in range(0, key_length):
        xor_cipher = b''
        for j in range(0, len(blocks)):
            xor_cipher += bytes([blocks[j][i]])
        single_byte_xor_ciphers.append(xor_cipher)

    # apply single byte attack on each row
    best_global_key = b''
    for xor_cipher in single_byte_xor_ciphers:
        best_key, best_plain, best_score = attack_single_byte(xor_cipher, lang)
        best_global_key += best_key

    return best_global_key
