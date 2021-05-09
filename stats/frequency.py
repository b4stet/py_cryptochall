from stats import language
from utils import encoder
from utils import bitwise


def get_byte_counts(data: bytes):
    observed = []

    # count
    counters = {}
    for byte in data:
        byte_hex = '{:02x}'.format(byte)
        if byte_hex not in counters.keys():
            counters[byte_hex] = 0
        counters[byte_hex] += 1

    # convert to list
    for byte_hex, count in counters.items():
        observed.append({
            'hex': byte_hex,
            'count': count
        })

    # sort
    return sorted(observed, key=lambda elt: elt['count'], reverse=True)


def get_language_score(data: bytes, lang: str):
    distribution = language.distribution.get(lang, None)
    if distribution is None:
        raise ValueError('stats.frequency.get_language_score: unknown language {}'.format(lang))

    score = 0
    for byte in data:
        letter = chr(byte).lower()
        theory = distribution.get(letter, None)
        if theory is not None:
            score += theory['freq']
    score = score/len(data)
    return score


def hamming_distance(a: bytes, b: bytes):
    distance = 0
    res = bitwise.xor(a, b)
    for byte in res:
        distance += bin(byte).count('1')

    return distance


def get_key_length(data: bytes, key_length_min: int, key_length_max: int, nb_block: int):
    best_key_length = 0
    best_distance = None

    for key_length in range(key_length_min, key_length_max + 1):
        if len(data) < key_length * nb_block:
            return best_key_length, best_distance

        average_distance = 0.0

        for i in range(0, nb_block - 1):
            offset_a = key_length * i
            offset_b = key_length * (i+1)
            a = data[offset_a:offset_a + key_length]
            b = data[offset_b:offset_b + key_length]
            distance = hamming_distance(a, b)
            average_distance += distance / key_length

        average_distance = average_distance / (nb_block - 1)
        if best_distance is None or average_distance < best_distance:
            best_distance = average_distance
            best_key_length = key_length

    return best_key_length, best_distance
