from oracle.base_handler import BaseHandler
from urllib.parse import urlparse, parse_qs
from crypter import aes
from utils import encoder, randomness


def create_handler_aes_ecb_cbc(key_byte_length: int):
    class AESwithECBorCBCHandler(BaseHandler):
        __KEY_LENGTH = key_byte_length

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def do_GET(self):
            data = self._parse_query_string().get('data', None)
            user_hex = ''
            if data is not None:
                user_hex = data[0]

            user_bytes = self._convert_or_raise_input(user_hex)

            # generate key and iv
            key = randomness.get_bytes(self.__KEY_LENGTH)
            iv = randomness.get_bytes(16)

            # pick ECB or CBC chaining mode randomly
            flip = bool(randomness.get_bits(1))

            # encrypt
            cipher_bytes = None
            if flip is True:
                cipher_bytes = aes.encrypt(user_bytes, key, 'ecb')
            else:
                cipher_bytes = aes.encrypt(user_bytes, key, 'cbc', iv)

                # remove iv
                cipher_bytes = cipher_bytes[16:]

            cipher_hex = encoder.bytes_to_hex(cipher_bytes)

            # send response
            self._send_response(cipher_hex)
            # self.send_response(200)
            # self.send_header("Content-type", "text/html")
            # self.end_headers()
            # self.wfile.write(bytes(cipher_hex, "utf-8"))

    return AESwithECBorCBCHandler
