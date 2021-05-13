import sys
import requests
from utils import encoder, padding


# oracle accept plaintext hex encoded, in a 'data' parameter
# oracle return cipher hex encoded

def get_response(url, data: bytes, verb='GET'):
    data_hex = encoder.bytes_to_hex(data)

    response = None
    if verb == 'GET':
        response = requests.get(url, params={'data': data_hex})

    if verb == 'POST':
        response = requests.post(url, data={'data': data_hex})
    response.encoding = 'utf-8'

    result = b''
    if response.status_code == '200':
        result = encoder.hex_to_bytes(response.text)
    else:
        result = encoder.utf8_to_bytes(response.reason)

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


# detect the offset from which we fully control encrypted blocks
# ie: server encrypts something like: unknown_fixed_data | user_input | secret
# we want to know when a fully controlled block starts:
# block 0          |block 1          |block 2          | ...
# unknown_fixed_data  | user_input ...                         | secret
# unknown_fixed_data  | user_prefix  | user_input_rest ...     | secret
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


# bruteforce secret in ECB chaining mode
# let secret = s(0)s(1).....s(n), the base block length is decremented after each bruteforce
# block 0          |block 1          |block 2          | ...
# unknown_fixed_data  | user_prefix  | base       |s(0)|s(1)...s(n) => get encryption of s(0), then bruteforce its value
# unknown_fixed_data  | user_prefix  | base  |s(0)|s(1)|s(2)...s(n) => get encryption of s(1), then bruteforce its value and so on
# ...
# unknown_fixed_data  | user_prefix  | s(0)......s(b-1)|s(b)...s(n) => get encryption of s(b-1), then bruteforce its value

# once s(0)...s(b-1) are known (b=block_byte_size), jump to bruteforce the next block in the secret, s(b)...s(2b-1)
# ... |block 1          |block 2          |block 3          | ...
# ...    | user_prefix  | base       |s(0)|s(1)...s(b-1)s(b)|s(b+1)...s(n) => get encryption of s(b), then bruteforce its value
# ...    | user_prefix  | base  |s(0)|s(1)|s(2)...s(b)s(b+1)|s(b+2)...s(n) => get encryption of s(b+1), then bruteforce its value and so on
# and so on
def bruteforce_ecb(url, block_byte_size: int, first_controlled_block_index: int, prefix: bytes):
    nb_oracle_calls = 0
    result = {
        'witnesses': {
            'collected': False,
            'nb_oracle_calls': 0,
        },
        'bruteforce': [],
        'secret': {
            'length': 0,
            'nb_oracle_calls': 0,
            'value': None,
        },
    }

    # store encryptions of [s(0)/s(b)/s(2b)/..., s(1)/s(b+1)/s(2b+1)/..., ...]
    witnesses = []
    for offset in range(0, block_byte_size):
        base_block = bytes([0]) * (block_byte_size - (offset + 1))
        base_block = prefix + base_block
        witness = get_response(url, base_block)
        result['witnesses']['nb_oracle_calls'] += 1
        witnesses.append(witness)
    result['witnesses']['collected'] = True
    nb_oracle_calls += result['witnesses']['nb_oracle_calls']

    # get length of the secret
    # thanks to pkcs7: full block of padding is added if plaintext is a multiple of block_byte_size
    initial_length = len(get_response(url, prefix))
    result['secret']['nb_oracle_calls'] += 1
    for i in range(1, block_byte_size):
        plain_bytes = prefix + bytes([0]) * i
        length = len(get_response(url, plain_bytes))
        result['secret']['nb_oracle_calls'] += 1
        if length > initial_length:
            result['secret']['length'] = initial_length - block_byte_size * first_controlled_block_index - i
            break
    nb_oracle_calls += result['secret']['nb_oracle_calls']

    # attack the secret block per block (s(0)..s(b-1), then s(b)..s(2b-1), etc)
    secret = b''
    block_index = first_controlled_block_index

    while len(secret) < result['secret']['length']:
        block_start = block_byte_size * block_index
        block_end = block_start + block_byte_size

        # bruteforce s(offset) inside the current block
        for offset in range(0, block_byte_size):
            attempt = {
                'block_index': block_index,
                'witness': None,
                'sent': None,
                'received': None,
                'nb_oracle_calls': 0,
            }

            # get witness block
            block_witness = witnesses[offset][block_start: block_end]
            attempt['witness'] = encoder.bytes_to_hex(block_witness)

            # build base block
            base_block = bytes([0]) * (block_byte_size - (offset + 1))
            base_block = prefix + base_block + secret

            # bruteforce s(offset): query oracle for all possible values until getting the witness
            for guess in range(0, 256):
                plain_bytes = base_block + encoder.int_to_bytes(guess)
                cipher_bytes = get_response(url, plain_bytes)
                attempt['nb_oracle_calls'] += 1
                block = cipher_bytes[block_start:block_end]
                if block == block_witness:
                    secret += encoder.int_to_bytes(guess)
                    attempt['sent'] = encoder.bytes_to_hex(plain_bytes)
                    attempt['received'] = encoder.bytes_to_hex(cipher_bytes)
                    result['bruteforce'].append(attempt)
                    nb_oracle_calls += attempt['nb_oracle_calls']
                    print('*', end='', flush=True)
                    break

            if len(secret) == result['secret']['length']:
                break
        block_index += 1

    print('')
    result['secret']['value'] = secret
    return result, nb_oracle_calls
