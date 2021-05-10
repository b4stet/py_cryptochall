import sys
from utils import encoder, bitwise
from stats import frequency
from crypter import xor, aes
from attack import xor_frequency
from datetime import datetime

# Set 1
print('[+] Set 1')
# Chall1
print(' | Chall 1 (convert hex to b64) ...', end='')
str_hex = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
str_b64_expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
str_b64_observed = encoder.hex_to_b64(str_hex)
assert str_b64_observed == str_b64_expected, 'Failed 1: Expected {}, got {}'.format(str_b64_expected, str_b64_observed)
print(' ok')

# Chall2
print(' | Chall 2 (xor operation) ...', end='')
a_hex = '1c0111001f010100061a024b53535009181c'
b_hex = '686974207468652062756c6c277320657965'
a_bytes = encoder.hex_to_bytes(a_hex)
b_bytes = encoder.hex_to_bytes(b_hex)
xor_bytes = bitwise.xor(a_bytes, b_bytes)
xor_hex_expected = '746865206b696420646f6e277420706c6179'
xor_hex_observed = encoder.bytes_to_hex(xor_bytes)
assert xor_hex_observed == xor_hex_expected, 'Failed 2: Expected {}, got {}'.format(xor_hex_expected, xor_hex_observed)
print(' ok')

# Chall3
print(' | Chall 3 (single byte xor cipher, frequency attack) ...', end='')
cipher_hex = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
cipher_bytes = encoder.hex_to_bytes(cipher_hex)
best_key, best_plain, _ = xor_frequency.attack_single_byte(cipher_bytes, 'english')
print(' ok: found key=0x{}, plain={}'.format(encoder.bytes_to_hex(best_key), encoder.bytes_to_utf8(best_plain)))

# Chall4
print(' | Chall 4 (detect single xor cipher, frequency attack) ...', end='')
plains = []
with open('./data/set1_chall4.txt', mode='r') as f:
    line = f.readline()
    index = 1
    while line:
        line = line.strip('\n')
        cipher_bytes = encoder.hex_to_bytes(line)
        best_key, best_plain, best_score = xor_frequency.attack_single_byte(cipher_bytes, 'english')
        plains.append({
            'index': index,
            'cipher': cipher_bytes,
            'plain': best_plain,
            'key': best_key,
            'score': best_score
        })
        index += 1
        line = f.readline()
plains.sort(key=lambda elt: elt['score'], reverse=True)
print(' ok: found xor cipher at index={}'.format(plains[0]['index']))
print('   | where cipher={}, frequency attack gave key={}, plain={}, score={}'.format(
    encoder.bytes_to_hex(plains[0]['cipher']),
    encoder.bytes_to_hex(plains[0]['key']),
    encoder.bytes_to_utf8(plains[0]['plain']).strip('\n'),
    plains[0]['score']
))

# Chall5
print(' | Chall 5 (implement repeating key xor cipher) ...', end='')
plain_utf8 = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
plain_bytes = encoder.utf8_to_bytes(plain_utf8)
key_utf8 = 'ICE'
key_bytes = encoder.utf8_to_bytes(key_utf8)
cipher_bytes = xor.encrypt(plain_bytes, key_bytes)
cipher_hex_observed = encoder.bytes_to_hex(cipher_bytes)
cipher_hex_expected = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527'
cipher_hex_expected += '2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
assert cipher_hex_observed == cipher_hex_expected, 'Failed 5: Expected {}, got {}'.format(cipher_hex_expected, cipher_hex_observed)
print(' ok')

# Chall6
print(' | Chall 6 (break repeating key xor)')
cipher_b64 = ''
with open('./data/set1_chall6.txt', mode='r') as f:
    lines = f.readlines()
    lines_stripped = [line.strip('\n') for line in lines]
    cipher_b64 = ''.join(lines_stripped)
cipher_bytes = encoder.b64_to_bytes(cipher_b64)
repeating_xor_key_expected = 'Terminator X: Bring the noise'

print('   | 6.1 (compute hamming distance) ...', end='')
hamming1_utf8 = 'this is a test'
hamming2_utf8 = 'wokka wokka!!!'
hamming1_bytes = encoder.utf8_to_bytes(hamming1_utf8)
hamming2_bytes = encoder.utf8_to_bytes(hamming2_utf8)
distance_observed = frequency.hamming_distance(hamming1_bytes, hamming2_bytes)
distance_expected = 37
assert distance_observed == distance_expected, 'Failed 6.1: Exptected {}, got {}'.format(distance_expected, distance_observed)
print(' ok')

print('   | 6.2 (guess key length) ...', end='')
best_key_length, best_distance = frequency.get_key_length(data=cipher_bytes, key_length_min=2, key_length_max=40, nb_block=20)
print(' ok: best key length found is {}, with a minimal hamming distance of {}'.format(best_key_length, best_distance))

print('   | 6.3 (split into block of key length bytes, transpose then apply single byte xor frequency attack) ...', end='')
best_key_bytes = xor_frequency.attack_repeating_key(cipher=cipher_bytes, key_length=best_key_length, lang='english')
best_key_utf8 = encoder.bytes_to_utf8(best_key_bytes)
assert best_key_utf8 == repeating_xor_key_expected, 'Failed 6.3: Exptected {}, got {}'.format(repeating_xor_key_expected, best_key_utf8)
print(' ok: found best repeating key is "{}"'.format(best_key_utf8))

# Chall 7
print(' | Chall 7 (AES-ECB decryption) ...', end='')
cipher_b64 = ''
with open('./data/set1_chall7.txt', mode='r') as f:
    lines = f.read().splitlines()
    cipher_b64 = ''.join(lines)
cipher_bytes = encoder.b64_to_bytes(cipher_b64)
key_utf8 = 'YELLOW SUBMARINE'
plain_expected_beginning = 'I\'m back and I\'m ringin\' the bell'
key_bytes = encoder.utf8_to_bytes(key_utf8)
plain_bytes = aes.decrypt(cipher_bytes, key_bytes, 'ecb')
plain_utf8 = encoder.bytes_to_utf8(plain_bytes)
assert plain_utf8.startswith("I'm back and I'm ringin' the bell") is True, 'Failed 7: Expected plain starting with "{}", got {}'.format(
    plain_expected_beginning, plain_utf8[:50]
)
print(' ok')

# Chall 8
print(' | Chall 8 (detect AES-ECB encryption) ...', end='')
ciphers_hex = []
with open('./data/set1_chall8.txt', mode='r') as f:
    ciphers_hex = f.read().splitlines()

guesses = []
for idx, cipher_hex in enumerate(ciphers_hex):
    # AES produces 128-bit blocks = 16-bytes blocks = 32-hexa blocks
    blocks = [cipher_hex[i:i+32] for i in range(0, len(cipher_hex), 32)]

    duplicates = list(set(block for block in blocks if blocks.count(block) > 1))
    if len(duplicates) > 0:
        guesses.append({
            'index': idx + 1,
            'cipher_hex': cipher_hex
        })
print(' ok: there is duplicated blocks at index {}, for cipher starting by {}'.format(guesses[0]['index'], guesses[0]['cipher_hex'][:32]))

# end of set 1
