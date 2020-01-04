from collections import OrderedDict

from scan2elk.templates.base import TplBase


class TplNessusPlugins(TplBase):

    def __init__(self):
        super().__init__()

    def render(self, search_result):
        plugins = OrderedDict()
        for finding in search_result.scan():
            try:
                plugins[finding.pluginID]
            except KeyError:
                plugins[finding.pluginID] =\
                    f'{finding.pluginID}: {finding.pluginName} ({finding.risk_factor}/{finding.severity})'

        return plugins.values()
