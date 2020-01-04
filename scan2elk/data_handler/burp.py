from scan2elk.data_handler.data_handler import DataHandler


class BurpHandler(DataHandler):
    NAME = 'burp'

    def __init__(self):
        super().__init__()

    def _load_mapping_config(self, file_name, ignore_error=False):
        return super()._load_mapping_config(file_name, True)
