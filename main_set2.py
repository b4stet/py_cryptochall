import sys
import threading
from datetime import datetime
from utils import encoder, bitwise, padding
from crypter import aes
from attack import cpa_guess_mode, cpa_retrieve_secret, cpa_forge_admin_profile
from oracle.oracle_server import OracleServer

# Set 2
print('[+] Set 2')

# Chall 9
print(' | Chall 9 (implement pkcs7 padding) ...', end='')
data_utf8 = 'YELLOW SUBMARINE'
padded_expected = b'YELLOW SUBMARINE\x04\x04\x04\x04'
data_bytes = encoder.utf8_to_bytes(data_utf8)
padded_bytes = padding.pad_pkcs7(data_bytes, 20)
assert padded_bytes == padded_expected, 'Failed 9: Expected {}, got {}'.format(padded_expected, padded_bytes)
print(' ok')

# Chall 10
print(' | Chall 10 (implement AES-CBC) ...', end='')
cipher_b64 = ''
with open('./data/set2_chall10.txt', mode='r') as f:
    lines = f.read().splitlines()
    cipher_b64 = ''.join(lines)
cipher_bytes = encoder.b64_to_bytes(cipher_b64)
iv = bytes([0])*16
key_utf8 = 'YELLOW SUBMARINE'
key_bytes = encoder.utf8_to_bytes(key_utf8)
plain_bytes = aes.decrypt_cbc_homemade(cipher_bytes, key_bytes, iv)
encrypted_bytes = aes.encrypt_cbc_homemade(plain_bytes, key_bytes, iv)
assert encrypted_bytes == cipher_bytes, 'Expected encryption starting by {}, got {}'.format(cipher_bytes[:10], encrypted_bytes[:10])
print(' ok')

# Chall 11
print(' | Chall 11 (implement Chosen Plaintext Attack (CPA) to detect ECB/CBC chaining mode)')
oracle = OracleServer('127.0.0.1', 8080, 'aes_ecb_cbc', 16)
server = oracle.get_server()
thread = threading.Thread(target=server.serve_forever,)
thread.daemon = True
thread.start()
print('   | oracle running at http://127.0.0.1:8080')
nb_runs = 5
nb_repeating_blocks = 3
result = cpa_guess_mode.guess_ecb_cbc(nb_repeating_blocks, nb_runs, 'http://127.0.0.1:8080')
server.shutdown()
server.server_close()
print('   | oracle stopped')
print('   | total number of calls to the oracle: {}'.format(result['total_oracle_calls']))
print('   | step 1: detected block byte size is {}, in {} oracle calls'.format(
    result['step1']['block_byte_size'], result['step1']['nb_oracle_calls']
))
print('   | step 2: chosen plaintext is {}x repeated 0x{}'.format(
    result['step2']['nb_repeating_blocks'], result['step2']['base_plain']
))
print('   | step 3: called {}x the oracle, guessing chaining mode each time'.format(result['step3']['nb_oracle_calls']))
for attempt in result['step3']['attempts']:
    print('     |- sent     0x{}'.format(attempt['sent']))
    print('     |  received 0x{}'.format(attempt['received']))
    print('     |  => chained with {}'.format(attempt['guessed']))

# Chall 12 & 14
print(' | Chall 12 and 14 (implement Chosen Plaintext Attack (CPA) to retrieve secret from encryption with ECB chaining mode)')
key_byte_size = 16
oracle = OracleServer('127.0.0.1', 8080, 'aes_ecb_secret', key_byte_size)
server = oracle.get_server()
thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
print('   | oracle running at http://127.0.0.1:8080')
result = cpa_retrieve_secret.attack_ecb('http://127.0.0.1:8080')
server.shutdown()
server.server_close()
print('   | oracle stopped')
print('   | total number of calls to the oracle to decrypt secret without knowing the key: {}'.format(result['total_oracle_calls']))
print('   | bruteforcing AES {}-bit key would take 1 call to the oracle then at most {:,} offline tests'.format(key_byte_size*8, 256**key_byte_size))
print('   | step 1: detected block byte size is {}, in {} oracle calls'.format(
    result['step1']['block_byte_size'], result['step1']['nb_oracle_calls']
))
print('   | step 2: verified oracle is chaining with ECB, in {} oracle calls'.format(result['step2']['nb_oracle_calls']))
print('   | step 3: offset of first fully controlled block obtained in {} calls to the oracle'.format(result['step3']['nb_oracle_calls']))
print('     | prefix to use for chosen plaintexts is 0x{} ({} bytes)'.format(
    result['step3']['chosen_plaintext_prefix'], len(result['step3']['chosen_plaintext_prefix'])//2
))
print('     | first controlled block is at index {}'.format(result['step3']['first_controlled_block_index']))
print('   | step 4: attack performed in {} calls to the oracle'.format(result['step4']['nb_oracle_calls']))
print('     | witnesses (secret encrypted starting from all possible offsets in a block) collected in {} calls to the oracle'.format(
    result['step4']['witnesses']['nb_oracle_calls']
))
print('     | secret length is {} bytes, obtained in {} calls to the oracle'.format(
    result['step4']['secret']['length'], result['step4']['secret']['nb_oracle_calls']
))
print('     | secret is: {}'.format(result['step4']['secret']['value']))
print('     | details of the bruteforce: [a, b, c, d] where')
print('     | a: offset of secret under bruteforce')
print('     | b: block index used to compare result with witness')
print('     | c: number of calls to the oracle before getting a match with the witness')
print('     | d: witness block to match')
for byte_offset, attempt in enumerate(result['step4']['bruteforce']):
    print('       |- [{:3}, {:2}, {:3} calls, 0x{}]'.format(byte_offset, attempt['block_index'], attempt['nb_oracle_calls'], attempt['witness']))
    print('       |  chosen plaintext {}'.format(encoder.hex_to_bytes(attempt['sent'])))

# Chall 13
print(' | Chall 13 (implement Chosen Plaintext Attack (CPA) to forge a valid encrypted admin profile, where encryption uses ECB chaining mode')
oracle = OracleServer('127.0.0.1', 8080, 'aes_ecb_profile', 16)
server = oracle.get_server()
thread = threading.Thread(target=server.serve_forever)
thread.daemon = True
thread.start()
print('   | oracle running at http://127.0.0.1:8080')
result = cpa_forge_admin_profile.abuse_ecb('http://127.0.0.1:8080')
server.shutdown()
server.server_close()
print('   | oracle stopped')
print('   | total number of calls to the oracle: {}'.format(result['total_oracle_calls']))
print('   | step 1: detected block byte size is {}, in {} oracle calls'.format(
    result['step1']['block_byte_size'], result['step1']['nb_oracle_calls']
))
print('   | step 2: verified oracle is chaining with ECB, in {} oracle calls'.format(result['step2']['nb_oracle_calls']))
print('   | step 3: forged an "admin" profile (oracle only creates "user" ones) in {} calls to the oracle'.format(result['step3']['nb_oracle_calls']))
print('     | sample: with email "{}", we get the profile 0x{}, which decrypt to "{}"'.format(
    result['step3']['sample']['email'], result['step3']['sample']['encrypted'], result['step3']['sample']['profile']
))
print('     | by choosing email "{}", we push "user" in a new block'.format(result['step3']['pushed_user_out']['email']))
print('       | got encrypted profile: 0x{}'.format(result['step3']['pushed_user_out']['encrypted']))
print('       | keeping:               0x{}'.format(result['step3']['pushed_user_out']['keeping']))
print('     | by choosing email {}, we get encryption of "admin" in a whole block'.format(result['step3']['admin_encryption']['email']))
print('       | got encrypted profile: 0x{}'.format(result['step3']['admin_encryption']['encrypted']))
print('       | keeping:               0x{}'.format(result['step3']['admin_encryption']['keeping']))
print('     | forged encrypted profile 0x{} decrypts to "{}"'.format(
    result['step3']['forged']['encrypted'], result['step3']['forged']['profile']
))

# Chall 15
print(' | Chall 14 (validate pkcs7 padding) ...', end='')
padding_ok = b'ICE ICE BABY\x04\x04\x04\x04'
padding_ko2 = b'ICE ICE BABY\x01\x02\x03\x04'
padding_ko1 = b'ICE ICE BABY\x05\x05\x05\x05'
padding_tests = [padding_ok, padding_ko1, padding_ko2]
padding_expectations = [True, False, False]
for test, expected in zip(padding_tests, padding_expectations):
    try:
        padding.unpad_pkcs7(test)
    except ValueError:
        if expected is False:
            pass
        else:
            raise
print(' ok')
