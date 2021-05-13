from oracle.base_handler import BaseHandler
from crypter import aes
from utils import encoder, randomness
import json


def create_handler_aes_ecb(key_byte_length: int):
    class AESwithECBHandler(BaseHandler):
        __KEY = randomness.get_bytes(key_byte_length)
        __FORBIDDEN_CHARS = ('=', '&')

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        # get encrypted profile from email
        def do_GET(self):
            data = self._parse_query_string().get('data', None)
            email_hex = ''
            if data is not None:
                email_hex = data[0]

            email_utf8 = encoder.hex_to_utf8(email_hex)
            forbidden = [c in email_utf8 for c in self.__FORBIDDEN_CHARS]
            if True in forbidden:
                self.send_error(400, 'email should not contain ({})'.format(','.join(self.__FORBIDDEN_CHARS)))

            # create user profile, encode then encrypt
            profile = self.__create_profile(email_utf8)
            encoded = self.__encode_profile(profile)
            encoded_bytes = encoder.utf8_to_bytes(encoded)
            cipher_bytes = aes.encrypt(encoded_bytes, self.__KEY, 'ecb')
            cipher_hex = encoder.bytes_to_hex(cipher_bytes)
            self._send_response(cipher_hex)

        # post encrypted profile to check validity
        def do_POST(self):
            content = self._parse_body()
            data = content.get(b'data', None)
            if data is None:
                self.send_error(400, 'received empty encrypted profile')

            encrypted_profile = encoder.hex_to_bytes(data[0].decode('utf-8'))
            encoded_bytes = aes.decrypt(encrypted_profile, self.__KEY, 'ecb')
            encoded_hex = encoder.bytes_to_hex(encoded_bytes)
            self._send_response(encoded_hex)

        def __create_profile(self, email):
            return {
                'email': email,
                'uid': 10,
                'role': 'user',
            }

        def __encode_profile(self, profile: dict):
            encoded = []
            encoded.append('email=' + profile['email'])
            encoded.append('uid=' + str(profile['uid']))
            encoded.append('role=' + profile['role'])

            return '&'.join(encoded)

        def __decode_profile(self, query_string):
            return dict(chunk.split('=') for chunk in query_string.split('&'))

    return AESwithECBHandler
