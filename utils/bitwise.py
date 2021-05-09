from utils import encoder


def xor(a: bytes, b: bytes):
    if len(a) != len(b):
        raise TypeError('utils.bitwise.xor: not equal-length arguments')

    res = b''
    for byte_a, byte_b in zip(a, b):
        res += encoder.int_to_bytes(byte_a ^ byte_b)

    return res
