from collections import OrderedDict

from scan2elk.templates.base import TplBase


class TplNessusPlugins(TplBase):

    def __init__(self):
        super().__init__()

    def render(self, search_result):
        plugins = OrderedDict()
        line = '{pid}: {pname} ({crit})'
        for finding in search_result.scan():
            try:
                plugins[finding.pluginID]
            except KeyError:
                plugins[finding.pluginID] = line.format(pid=finding.pluginID, pname=finding.pluginName,
                                                        crit=finding.risk_factor)

        return plugins.values()
