def pad_pkcs7(data: bytes, block_byte_length: int):
    padded = data
    nb_missing_byte = block_byte_length - len(data) % block_byte_length
    padding = bytes([nb_missing_byte]) * nb_missing_byte
    if nb_missing_byte == 0:
        padding = bytes([block_byte_length]) * block_byte_length
    padded += padding

    return padded


def unpad_pkcs7(data: bytes):
    nb_padded = data[-1]

    # validate that data ends with nb_padded times the byte 'nb_padded'
    for i in range(0, nb_padded):
        if data[-1 - i] != nb_padded:
            raise ValueError('Invalid padding')
    return data[:-nb_padded]
