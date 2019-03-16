from scan2elk.data_handler.data_handler import DataHandler


class SslscanHandler(DataHandler):
    NAME = 'sslscan'

    def __init__(self):
        super().__init__()
