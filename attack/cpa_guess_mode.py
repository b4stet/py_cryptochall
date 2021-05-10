from utils import encoder
import requests
from attack import query_oracle


# requirements for success:
# - oracle accept plaintext hex encoded, in a 'data' parameter
# - oracle return cipher hex encoded
def guess_ecb_cbc(nb_repeating_blocks, nb_runs, url):
    result = {
        'total_oracle_calls': 0,
        'step1': {},
        'step2': {},
        'step3': {},
    }

    # step 1: detect block size
    block_byte_size, nb_oracle_calls = query_oracle.get_block_size(url)
    result['step1'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'block_byte_size': block_byte_size,
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 2: create a repeating plain
    base_bytes = bytes([00])
    base_bytes += b'A' * (block_byte_size - 1)
    plain_bytes = base_bytes * nb_repeating_blocks
    result['step2'] = {
        'nb_repeating_blocks': nb_repeating_blocks,
        'base_plain': encoder.bytes_to_hex(base_bytes),
    }

    # step 3: query the oracle with that special plain and analyze the cipher
    result['step3'] = {
        'nb_oracle_calls': 0,
        'attempts': [],
    }
    for i in range(0, nb_runs):
        attempt = {
            'sent': encoder.bytes_to_hex(plain_bytes),
            'received': None,
            'guessed': None,
        }
        cipher_bytes = query_oracle.get_response(url, plain_bytes)
        attempt['received'] = encoder.bytes_to_hex(cipher_bytes)
        result['step3']['nb_oracle_calls'] += 1

        blocks = [cipher_bytes[i:i+block_byte_size] for i in range(0, len(cipher_bytes), block_byte_size)]
        duplicates = list(set(block for block in blocks if blocks.count(block) > 1))

        # plain with identical blocks and cipher too: it is ecb
        if len(duplicates) > 0:
            attempt['guessed'] = 'ecb'
        else:
            attempt['guessed'] = 'cbc'

        result['step3']['attempts'].append(attempt)
        print('*', end='', flush=True)

    print('')
    result['total_oracle_calls'] += result['step3']['nb_oracle_calls']
    return result
