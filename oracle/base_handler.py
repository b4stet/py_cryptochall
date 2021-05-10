from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, parse_qsl
from utils import encoder


class BaseHandler(BaseHTTPRequestHandler):
    def _parse_query_string(self):
        return parse_qs(urlparse(self.path).query, encoding='utf-8')

    def _parse_body(self):
        content_length = int(self.headers.get('content-length'))
        data = self.rfile.read(content_length)
        return parse_qs(data, encoding='utf-8')

    def _convert_or_raise_input(self, data: str):
        try:
            data_bytes = encoder.hex_to_bytes(data)
        except Exception as err:
            raise ValueError('Expected hex encoded data. Got error {}'.format(str(err)))

        return data_bytes

    def _send_response(self, message):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(message, "utf-8"))

    def log_request(self, code='-', size='-'):
        return
