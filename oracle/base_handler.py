from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from utils import encoder


class BaseHandler(BaseHTTPRequestHandler):
    def _parse_query_string(self):
        return parse_qs(urlparse(self.path).query)

    def _convert_or_raise_input(self, data: str):
        try:
            data_bytes = encoder.hex_to_bytes(data)
        except Exception as err:
            raise ValueError('Expected hex encoded data. Got error {}'.format(str(err)))

        return data_bytes

    def log_request(self, code='-', size='-'):
        return
