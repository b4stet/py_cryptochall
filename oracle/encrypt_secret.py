from oracle.base_handler import BaseHandler
from urllib.parse import urlparse, parse_qs
from crypter import aes
from utils import encoder, randomness


def MakeAESwithECBHandler(key_byte_length: int):
    secret_b64 = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGll'
    secret_b64 += 'cyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    before = b'X' * randomness.get_int(0, 24)

    class AESwithECBHandler(BaseHandler):
        __KEY = randomness.get_bytes(key_byte_length[0])
        __SECRET = encoder.b64_to_bytes(secret_b64)

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        def do_GET(self):
            data = self._parse_query_string().get('data', None)
            user_hex = ''
            if data is not None:
                user_hex = data[0]

            user_bytes = self._convert_or_raise_input(user_hex)

            # append secret
            plain_bytes = before + user_bytes + self.__SECRET

            # encrypt
            cipher_bytes = aes.encrypt(plain_bytes, self.__KEY, 'ecb')
            cipher_hex = encoder.bytes_to_hex(cipher_bytes)

            # send response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(bytes(cipher_hex, "utf-8"))

    return AESwithECBHandler
