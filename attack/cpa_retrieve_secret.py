from utils import encoder, padding
from attack import query_oracle
import requests


# requirement for success: secret is appended to attacker controlled plaintext + oracle pads with pcks7
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
    # ie: server encrypts something like: unknown_fixed_data | user_input | secret
    # we want to know when a fully controlled block starts:
    # block 0          |block 1          |block 2          | ...
    # unknown_fixed_data  | user_input ...                         | secret
    # unknown_fixed_data  | user_prefix  | user_input_rest ...     | secret
    first_controlled_block_index, prefix_length, nb_oracle_calls = query_oracle.get_offset_first_controlled_block(url, block_byte_size)
    prefix_bytes = bytes([0]) * prefix_length
    result['step3'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'first_controlled_block_index': first_controlled_block_index,
        'chosen_plaintext_prefix': encoder.bytes_to_hex(prefix_bytes),
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 4: extract secret byte per byte
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

    result['step4'] = {
        'nb_oracle_calls': 0,
        'witnesses': {
            'collected': False,
            'nb_oracle_calls': 0,
        },
        'bruteforce': [],
        'secret': None,
    }

    # store encryptions of [s(0)/s(b)/s(2b)/..., s(1)/s(b+1)/s(2b+1)/..., ...]
    witnesses = []
    for offset in range(0, block_byte_size):
        base_block = bytes([0]) * (block_byte_size - (offset + 1))
        base_block = prefix_bytes + base_block
        witness = query_oracle.get_response(url, base_block)
        result['step4']['witnesses']['nb_oracle_calls'] += 1
        witnesses.append(witness)
    result['step4']['witnesses']['collected'] = True
    result['step4']['nb_oracle_calls'] += result['step4']['witnesses']['nb_oracle_calls']

    # attack the secret block per block (s(0)..s(b-1), then s(b)..s(2b-1), etc)
    secret = b''
    finished = False
    block_index = first_controlled_block_index

    while finished is False:
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
            base_block = prefix_bytes + base_block + secret

            # bruteforce s(offset): query oracle for all possible values until getting the witness
            found = False
            for guess in range(0, 256):
                plain_bytes = base_block + encoder.int_to_bytes(guess)
                cipher_bytes = query_oracle.get_response(url, plain_bytes)
                attempt['nb_oracle_calls'] += 1
                block = cipher_bytes[block_start:block_end]
                if block == block_witness:
                    secret += encoder.int_to_bytes(guess)
                    found = True
                    attempt['sent'] = encoder.bytes_to_hex(plain_bytes)
                    attempt['received'] = encoder.bytes_to_hex(cipher_bytes)
                    result['step4']['bruteforce'].append(attempt)
                    result['step4']['nb_oracle_calls'] += attempt['nb_oracle_calls']
                    print('*', end='', flush=True)
                    break

            # if no match found, we are at the end of the secret, because of pkcs7 padding
            # last match was for with 0x01
            # next plain with be with 0x....01xx instead of 0x....02xx (to match on 0202): no match possible
            if found is False:
                finished = True
                break
        block_index += 1

    print('')
    secret = padding.unpad_pkcs7(secret)
    result['step4']['secret'] = secret
    result['total_oracle_calls'] += result['step4']['nb_oracle_calls']

    return result
