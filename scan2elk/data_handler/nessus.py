from scan2elk.data_handler.data_handler import DataHandler


class NessusHandler(DataHandler):

    NAME = 'nessus'

    def __init__(self):
        super().__init__()
        # include host mappings in finding mappings, since the same fields are being used
        self.finding_mapping = {**self.host_mapping, **self.finding_mapping}
