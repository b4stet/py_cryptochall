from utils import encoder, padding
from attack import query_oracle
import requests


# requirement for success:
# - secret is appended to attacker controlled plaintext
# - oracle chains with ECB
# - oracle pads with a method (eg. pcks7) that adds a full block of padding if plain is a multiple of block size
# - oracle accept plaintext hex encoded, in a 'data' parameter
# - oracle return cipher hex encoded
def attack_ecb(url):
    result = {
        'total_oracle_calls': 0,
        'step1': {},
        'step2': {},
        'step3': {},
        'step4': {},
    }

    # step 1: detect block size
    block_byte_size, nb_oracle_calls = query_oracle.get_block_size(url)
    result['step1'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'block_byte_size': block_byte_size,
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 2: verify chaining mode is ECB
    is_ecb, nb_oracle_calls = query_oracle.is_ecb_mode(url, block_byte_size)
    if is_ecb is False:
        raise RuntimeError('The oracle is not chaining blocks in ECB mode. Aborting.')
    result['step2'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'verified_ecb': True,
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 3: detect the offset from which we fully control encrypted blocks
    first_controlled_block_index, prefix_length, nb_oracle_calls = query_oracle.get_offset_first_controlled_block(url, block_byte_size)
    prefix_bytes = bytes([0]) * prefix_length
    result['step3'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'first_controlled_block_index': first_controlled_block_index,
        'chosen_plaintext_prefix': encoder.bytes_to_hex(prefix_bytes),
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 4: extract secret byte per byte
    result['step4'], nb_oracle_calls = query_oracle.bruteforce_ecb(url, block_byte_size, first_controlled_block_index, prefix_bytes)
    result['step4']['nb_oracle_calls'] = nb_oracle_calls
    result['total_oracle_calls'] += nb_oracle_calls

    return result
