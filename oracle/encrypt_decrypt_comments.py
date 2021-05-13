from oracle.base_handler import BaseHandler
from crypter import aes
from utils import encoder, randomness
import json
from urllib.request import quote


def create_handler_aes_cbc(key_byte_length: int):
    class AESwithCBCHandler(BaseHandler):
        __KEY = randomness.get_bytes(key_byte_length)
        __ESCAPE_CHARS = ('=', ';')

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)

        # get encrypted comment from user data
        def do_GET(self):
            data = self._parse_query_string().get('data', None)
            data_hex = ''
            if data is not None:
                data_hex = data[0]
            data_utf8 = encoder.hex_to_utf8(data_hex)

            # create comment, encode then encrypt
            comment = self.__create_comment(data_utf8)
            encoded = self.__encode_comment(comment)
            encoded_bytes = encoder.utf8_to_bytes(encoded)

            iv = randomness.get_bytes(16)
            cipher_bytes = aes.encrypt(encoded_bytes, self.__KEY, 'cbc', iv)

            # remove iv
            cipher_hex = encoder.bytes_to_hex(cipher_bytes)
            self._send_response(cipher_hex)

        # post encrypted comment to check content (get decryption)
        def do_POST(self):
            content = self._parse_body()
            data = content.get(b'data', None)
            if data is None:
                self.send_error(400, 'received empty encrypted comment')

            encrypted_comment = encoder.hex_to_bytes(data[0].decode('utf-8'))
            iv = encrypted_comment[:16]
            try:
                encoded_bytes = aes.decrypt(encrypted_comment[16:], self.__KEY, 'cbc', iv)
            except Exception as err:
                self.send_error(400, str(err))

            encoded_hex = encoder.bytes_to_hex(encoded_bytes)
            self._send_response(encoded_hex)

        def __create_comment(self, user_data):
            # url encode special characters (among which '=' and ';')
            return {
                'comment1': quote('cooking MCs'),
                'user_data': quote(user_data),
                'comment2': quote(' like a pound of bacon'),
            }

        def __encode_comment(self, comment: dict):
            encoded = []
            encoded.append('comment1=' + comment['comment1'])
            encoded.append('userdata=' + comment['user_data'])
            encoded.append('comment2=' + comment['comment2'])

            return ';'.join(encoded)

        def __decode_comment(self, string):
            return dict(chunk.split('=') for chunk in string.split(';'))

    return AESwithCBCHandler
