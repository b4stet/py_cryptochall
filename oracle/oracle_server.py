from http.server import HTTPServer
from oracle import encrypt_mode, encrypt_secret, encrypt_profile


class OracleServer():
    __HANDLERS = {
        'aes_ecb_cbc': {
            'handler': encrypt_mode.create_handler_aes_ecb_cbc,
            'nb_args': 1,
        },
        'aes_ecb_secret': {
            'handler': encrypt_secret.create_handler_aes_ecb,
            'nb_args': 1,
        },
        'aes_ecb_profile': {
            'handler': encrypt_profile.create_handler_aes_ecb,
            'nb_args': 1,
        }
    }

    def __init__(self, hostname, port, handler_name, *args):
        self.__handler_name = handler_name
        self.__args = args
        self.__hostname = hostname
        self.__port = port

    def get_server(self):
        handler_config = self.__HANDLERS.get(self.__handler_name, None)
        if handler_config is None:
            raise ValueError('Unkown handler {}'.format(self.__handler_name))

        if len(self.__args) != handler_config['nb_args']:
            raise ValueError('Expected {} args for handler {}. Got {}'.format(handler_config['nb_args'], self.__handler_name, len(self.__args)))

        handler = None
        if handler_config['nb_args'] > 0:
            handler = handler_config['handler'](*self.__args)
        else:
            handler = handler_config['handler']

        return HTTPServer((self.__hostname, self.__port), handler)
