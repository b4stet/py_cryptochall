from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits


# from /dev/urandom
def get_bytes(nb_bytes: int):
    return get_random_bytes(nb_bytes)


def get_bits(nb_bits: int):
    return getrandbits(nb_bits)


def get_unif01():
    r = get_random_bytes(128)
    return int.from_bytes(r, byteorder='big', signed=False)/(1 << 1024)


def get_int(nmin, nmax):
    return int(nmin + (nmax - nmin)*get_unif01())
