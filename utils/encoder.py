import base64


def b64_to_hex(data: str):
    return base64.b64decode(data).hex()


def hex_to_b64(data: str):
    return base64.b64encode(bytes.fromhex(data)).decode('utf-8')


def b64_to_bytes(data: str):
    return base64.b64decode(data)


def bytes_to_b64(data: bytes):
    return base64.b64encode(data).decode('utf-8')


def bytes_to_hex(data: bytes):
    return data.hex()


def hex_to_bytes(data: str):
    return bytes.fromhex(data)


def bytes_to_ascii(data: bytes):
    return data.decode('utf-8')


def ascii_to_bytes(data: str):
    return data.encode('utf-8')


def ascii_to_b64(data: str):
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')


def b64_to_ascii(data: str):
    return base64.b64decode(data).decode('utf-8')


def ascii_to_hex(data: str):
    return data.encode('utf-8').hex()


def hex_to_ascii(data: str):
    return bytes.fromhex(data).decode('utf-8')


def int_to_hex(data: int):
    return '{:02x}'.format(data)


def hex_to_int(data: str):
    return int(data, 16)


def int_to_bytes(data: int):
    nb_byte = data.bit_length() // 8
    if data.bit_length() % 8 != 0 or nb_byte == 0:
        nb_byte += 1
    return data.to_bytes(nb_byte, byteorder='big', signed=False)


def bytes_to_int(data: bytes):
    return int.from_bytes(data, byteorder='big', signed=False)
