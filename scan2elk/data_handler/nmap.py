from scan2elk.data_handler.data_handler import DataHandler


class NmapHandler(DataHandler):

    NAME = 'nmap'

    def __init__(self):
        super().__init__()

