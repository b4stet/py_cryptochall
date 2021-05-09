from Crypto.Cipher import AES
from utils import padding, bitwise

chaining_modes = {
    'ecb': AES.MODE_ECB,
    'cbc': AES.MODE_CBC,
}


def encrypt(plain: bytes, key: bytes, chaining_mode: str, iv=None):
    if chaining_mode not in chaining_modes.keys():
        raise ValueError('crypter.aes.encrypt: Unknown chaining_mode')

    if iv is None:
        crypter = AES.new(key, chaining_modes[chaining_mode])
    else:
        crypter = AES.new(key, chaining_modes[chaining_mode], iv)

    blocks_plain = [plain[i:i+16] for i in range(0, len(plain), 16)]
    if len(blocks_plain[-1]) < 16:
        blocks_plain[-1] = padding.pad_pkcs7(blocks_plain[-1], 16)
    plain_padded = b''.join(blocks_plain)

    return crypter.encrypt(plain_padded)


def decrypt(cipher: bytes, key: bytes, chaining_mode: str, iv=None, unpad=True):
    if chaining_mode not in chaining_modes.keys():
        raise ValueError('crypter.aes.decrypt: Unknown chaining_mode')

    if iv is None:
        crypter = AES.new(key, chaining_modes[chaining_mode])
    else:
        crypter = AES.new(key, chaining_modes[chaining_mode], iv)

    plain = crypter.decrypt(cipher)
    if unpad is True:
        plain = padding.unpad_pkcs7(plain)

    return plain


def encrypt_cbc_homemade(plain: bytes, key: bytes, iv: bytes):
    blocks_plain = [plain[i:i+16] for i in range(0, len(plain), 16)]
    if len(blocks_plain[-1]) < 16:
        blocks_plain[-1] = padding.pad_pkcs7(blocks_plain[-1], 16)

    cipher = b''
    prev = iv
    for block_plain in blocks_plain:
        xored = bitwise.xor(prev, block_plain)
        block_cipher = encrypt(xored, key, 'ecb')
        prev = block_cipher
        cipher += block_cipher

    return cipher


def decrypt_cbc_homemade(cipher: bytes, key: bytes, iv: bytes):
    blocks_cipher = [cipher[i:i+16] for i in range(0, len(cipher), 16)]

    plain = b''
    prev = iv
    for block_cipher in blocks_cipher:
        block_decrypted = decrypt(block_cipher, key, 'ecb', unpad=False)
        unxored = bitwise.xor(prev, block_decrypted)
        plain += unxored
        prev = block_cipher

    plain = padding.unpad_pkcs7(plain)
    return plain
