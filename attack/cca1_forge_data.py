from utils import encoder, padding
from attack import query_oracle
import requests


# requirements for success:
# - oracle chains with ECB
# - oracle pads with pkcs7
# - profile is encoded in a fixed order, ending by the role
# - the uid is fixed
# - oracle accept plaintext hex encoded, in a 'data' parameter
# - oracle return cipher hex encoded
# note: because of forbidden characters, we cannot launch a CPA attack to decrypt a profile on our own
def create_admin_profile_ecb(url, role_user, role_target):
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

    # step 2: verify chaining mode is ECB
    is_ecb, nb_oracle_calls = query_oracle.is_ecb_mode(url, block_byte_size)
    if is_ecb is False:
        raise RuntimeError('The oracle is not chaining blocks in ECB mode. Aborting.')
    result['step2'] = {
        'nb_oracle_calls': nb_oracle_calls,
        'verified_ecb': True,
    }
    result['total_oracle_calls'] += nb_oracle_calls

    # step 3: forge an admin profile
    result['step3'] = {
        'nb_oracle_calls': 0,
    }
    # request a decryption example to know the structure
    email_bytes = b'email@example.com'
    profile_encrypted = query_oracle.get_response(url, email_bytes)
    profile_bytes = query_oracle.get_response(url, profile_encrypted, 'POST')
    result['step3']['nb_oracle_calls'] += 1
    result['step3']['sample'] = {
        'email': encoder.bytes_to_utf8(email_bytes),
        'profile': encoder.bytes_to_utf8(profile_bytes),
        'encrypted': encoder.bytes_to_hex(profile_encrypted),
    }

    # choose an email so that low_privileged role (eg. 'user') get encrypted in a new block
    # let profile = before_email|email|before_role|user
    # block0              |block1              |block2
    # before_email|emaiiii|iiiiiiil|before_role|user
    before_email, after_email = profile_bytes.split(email_bytes, 1)
    before_role = after_email.split(encoder.utf8_to_bytes(role_user), 1)[0]
    email_length = block_byte_size - (len(before_email) + len(before_role)) % block_byte_size

    domain = b'@example.com'
    while email_length < min(len(domain), block_byte_size):
        email_length += block_byte_size
    username = b'a' * (email_length - 12)
    email_bytes = username + domain
    nb_blocks_to_keep = (len(before_email) + len(email_bytes) + len(before_role)) // block_byte_size

    profile_encrypted = query_oracle.get_response(url, email_bytes)
    result['step3']['nb_oracle_calls'] += 1
    forged = profile_encrypted[:block_byte_size * nb_blocks_to_keep]
    result['step3']['pushed_user_out'] = {
        'email': encoder.bytes_to_utf8(email_bytes),
        'encrypted': encoder.bytes_to_hex(profile_encrypted),
        'keeping': encoder.bytes_to_hex(forged),
    }

    # leveraging pkcs7 padding, get encryption of 'admin' alone
    # block0              |block1              |block2
    # before_email|prefix |admin               |after_email
    prefix = b'a' * (block_byte_size - len(before_email) % block_byte_size)
    email_bytes = padding.pad_pkcs7(encoder.utf8_to_bytes(role_target), block_byte_size)
    email_bytes = prefix + email_bytes
    profile_encrypted = query_oracle.get_response(url, email_bytes)
    result['step3']['nb_oracle_calls'] += 1
    nb_block_to_skip = (len(before_email) + len(prefix)) // block_byte_size
    block_start = block_byte_size * nb_block_to_skip
    block_end = block_start + block_byte_size
    forged += profile_encrypted[block_start: block_end]
    result['step3']['admin_encryption'] = {
        'email': email_bytes,
        'encrypted': encoder.bytes_to_hex(profile_encrypted),
        'keeping': ' '*block_byte_size*nb_block_to_skip*2 + encoder.bytes_to_hex(profile_encrypted[block_start: block_end]),
    }

    # verify the forged encrypted profile
    profile = query_oracle.get_response(url, forged, 'POST')
    result['step3']['nb_oracle_calls'] += 1
    result['step3']['forged'] = {
        'encrypted': encoder.bytes_to_hex(forged),
        'profile': encoder.bytes_to_utf8(profile),
    }
    result['total_oracle_calls'] += result['step3']['nb_oracle_calls']

    return result
