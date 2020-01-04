from scan2elk.templates.servicelist import TplServiceList


class TplServiceListTexList(TplServiceList):

    def __init__(self):
        super().__init__()

    def render(self, search_result):
        self.get_data(search_result)
        output = self.get_plugin_output()
        output.extend(['\\item {}'.format(entry) for entry in self.get_data_output()])

        return output
