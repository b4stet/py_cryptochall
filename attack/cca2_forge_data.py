from utils import encoder, padding, bitwise
from attack import query_oracle
from urllib.request import quote


# requirements for success:
# - oracle chains with ECB
# - oracle pads with pkcs7
# - profile is encoded in a fixed order, ending by the role
# - the uid is fixed
# - oracle accept plaintext hex encoded, in a 'data' parameter
# - oracle return cipher hex encoded
# note: because of forbidden characters, we cannot launch a CPA attack to decrypt a profile on our own
def create_admin_profile_ecb(url, role_user: str, role_target: str):
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
    result['step3']['nb_oracle_calls'] += 2
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
    username = b'a' * (email_length - len(domain))
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
        'prefix': encoder.bytes_to_utf8(prefix),
        'admin_block_index': nb_block_to_skip,
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


# requirements for success:
# - oracle chains with CBC
# - comment is encoded in a fixed order, with user data not in first block
# - byte length of target_data is at most 1 block
# - oracle accept plaintext hex encoded, in a 'data' parameter
# - oracle return cipher hex encoded
def add_admin_cbc(url, target_data: str):
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

    if len(target_data) > block_byte_size:
        raise ValueError('Target data too long. Should be at most {} bytes'.format(block_byte_size))

    # step 2: get a decryption sample to know the structure
    result['step2'] = {
        'nb_oracle_calls': 0,
    }

    # encrypt/decrypt a sample
    sample_bytes = b'foobar' + encoder.utf8_to_bytes(target_data)
    comment_encrypted = query_oracle.get_response(url, sample_bytes)
    result['step2']['nb_oracle_calls'] += 1

    comment_bytes = query_oracle.get_response(url, comment_encrypted, 'POST')
    result['step2']['nb_oracle_calls'] += 1
    result['step2'].update({
        'sample': encoder.bytes_to_utf8(sample_bytes),
        'comment': encoder.bytes_to_utf8(comment_bytes),
        'encrypted': encoder.bytes_to_hex(comment_encrypted[16:]),
    })
    result['total_oracle_calls'] += result['step2']['nb_oracle_calls']

    # find prefix to ensure we know where we will inject our target data
    # +1 because of iv
    sample_quoted = quote(encoder.bytes_to_utf8(sample_bytes))
    before_user_input = comment_bytes.split(encoder.utf8_to_bytes(sample_quoted), 1)[0]
    prefix = b''
    if len(before_user_input) % block_byte_size != 0:
        prefix = b'x' * (block_byte_size - len(before_user_input) % block_byte_size)
    first_controlled_block_index = (len(before_user_input) + len(prefix)) // block_byte_size + 1
    result['step2'].update({
        'chosen_plaintext_prefix': encoder.bytes_to_hex(prefix),
        'first_controlled_block_index': first_controlled_block_index,
    })

    # step 3: inject data to add data (eg. 'admin=true' or alike)
    result['step3'] = {
        'nb_oracle_calls': 0,
    }

    # get a cipher for a string as long as the target we want
    witness = b'a' * len(target_data)
    ref_bytes = prefix + witness
    comment_encrypted = query_oracle.get_response(url, ref_bytes)
    comment_bytes = query_oracle.get_response(url, comment_encrypted, 'POST')
    result['step3']['nb_oracle_calls'] += 2
    result['step3']['reference'] = {
        'sent': encoder.bytes_to_utf8(ref_bytes),
        'received': encoder.bytes_to_hex(comment_encrypted),
        'comment': encoder.bytes_to_utf8(comment_bytes),
    }

    # leverage CBC chaining mode
    # starting from the global bloc matching cipher/plain:
    #       |cipher0                 |cipher1                 |cipher2
    #       |before_user_input|prefix|000000000           |after_user_input

    # when decrypting:
    #       |before_user_input|prefix|000000000           |after_user_input
    # iv    |plain0                  |plain1                  |plain2
    #       |dec(cipher0) xor iv     |dec(cipher1) xor cipher0|dec(cipher2) xor cipher1

    # because xor is a bitwise operation, wisely tampering cipher0 (cipher0') will force the oracle to decrypt plain1 to the thing we want (plain1')
    # of course, plain0 will become gribbish
    # we know: cipher0, plain1
    # plain1  = 00000000000 | after_user_input
    # plain1' = target_data | after_user_input
    # plain1  = dec(cipher1) xor cipher0   <=> dec(cipher1) = plain1 xor cipher0
    # plain1' = dec(cipher1) xor cipher0'  <=> cipher0' = plain1' xor dec(cipher1)
    # => cipher0' = plain1' xor plain1 xor cipher0

    # note: because after_user_input xor after_user_input = 0, we will just pad plain1 and plain1' with 0x00 directly
    block_start = block_byte_size * (first_controlled_block_index - 1)
    block_end = block_start + block_byte_size
    cipher0 = comment_encrypted[block_start: block_end]

    plain1 = witness + bytes([0]) * (block_byte_size - len(target_data))
    plain1prime = encoder.utf8_to_bytes(target_data) + bytes([0]) * (block_byte_size - len(target_data))

    cipher0prime = bitwise.xor(plain1, plain1prime)
    cipher0prime = bitwise.xor(cipher0prime, cipher0)
    forged = comment_encrypted[:block_start] + cipher0prime + comment_encrypted[block_end:]

    comment_bytes = query_oracle.get_response(url, forged, 'POST')
    result['step3']['forging'] = {
        'plain_block_target_index': first_controlled_block_index,
        'cipher_block_to_tamper': encoder.bytes_to_hex(cipher0),
        'plain_current': encoder.bytes_to_hex(plain1),
        'plain_target': encoder.bytes_to_hex(plain1prime),
        'cipher_block_tampered': encoder.bytes_to_hex(cipher0prime),
        'sent': encoder.bytes_to_hex(forged),
        'comment': comment_bytes,
    }
    result['step3']['nb_oracle_calls'] += 1
    result['total_oracle_calls'] += result['step3']['nb_oracle_calls']

    return result
