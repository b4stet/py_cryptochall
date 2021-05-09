import requests
from utils import encoder


def get_response(url, data: bytes):
    data_hex = encoder.bytes_to_hex(data)
    response = requests.get(url, params={'data': data_hex})
    response.encoding = 'utf-8'
    return encoder.hex_to_bytes(response.text)


def get_block_size(url: str):
    block_byte_size = 0
    nb_oracle_calls = 0

    test = False
    plain_bytes = b'A'
    cipher_bytes = get_response(url, plain_bytes)
    nb_oracle_calls += 1
    init_length = len(cipher_bytes)

    while test is False:
        plain_bytes += b'A'
        cipher_bytes = get_response(url, plain_bytes)
        nb_oracle_calls += 1

        if len(cipher_bytes) > init_length:
            test = True
            block_byte_size = len(cipher_bytes) - init_length

    return block_byte_size, nb_oracle_calls


def is_ecb_mode(url: str, block_byte_size: int):
    plain_bytes = bytes([00])
    plain_bytes += b'A' * (block_byte_size - 1)
    plain_bytes = plain_bytes * 10

    cipher_bytes = get_response(url, plain_bytes)
    nb_oracle_calls = 1

    blocks = [cipher_bytes[i:i+block_byte_size] for i in range(0, len(cipher_bytes), block_byte_size)]
    duplicates = list(set(block for block in blocks if blocks.count(block) > 1))

    # plain with identical blocks (10x to be sure :p) and cipher too: it is ecb
    is_ecb = False
    if len(duplicates) > 0:
        is_ecb = True

    return is_ecb, nb_oracle_calls


def get_offset_first_controlled_block(url, block_byte_size):
    nb_oracle_calls = 0

    plain_a = b'A' * block_byte_size
    plain_b = b'B' * block_byte_size
    cipher_a = get_response(url, plain_a)
    cipher_b = get_response(url, plain_b)
    nb_oracle_calls += 2

    first_different_block_offset = 0
    nb_blocks = len(cipher_a) // block_byte_size
    for i in range(0, nb_blocks):
        block_a = cipher_a[i*block_byte_size:(i+1)*block_byte_size]
        block_b = cipher_b[i*block_byte_size:(i+1)*block_byte_size]
        if block_a != block_b:
            first_different_block_offset = i
            break

    nb_bytes_before_new_block = 0
    plain_a_witness = b'A'
    plain_b_witness = b'B'
    for i in range(0, block_byte_size):
        prefix = bytes([0]) * i
        plain_a = prefix + plain_a_witness
        plain_b = prefix + plain_b_witness
        cipher_a = get_response(url, plain_a)
        cipher_b = get_response(url, plain_b)
        nb_oracle_calls += 2

        block_a = cipher_a[first_different_block_offset:first_different_block_offset + block_byte_size]
        block_b = cipher_b[first_different_block_offset:first_different_block_offset + block_byte_size]
        if block_a == block_b:
            nb_bytes_before_new_block = i
            break

    first_controlled_block = first_different_block_offset
    if nb_bytes_before_new_block > 0:
        first_controlled_block += 1

    return first_controlled_block, nb_bytes_before_new_block, nb_oracle_calls
