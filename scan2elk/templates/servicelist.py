from collections import OrderedDict

from scan2elk.templates.base import TplBase


class TplServiceList(TplBase):

    def __init__(self):
        super().__init__()
        self.plugins = OrderedDict()
        self.data = {}

    def get_data(self, search_result):
        # reset data
        self.data = {}
        pline = '{pid}: {pname} ({crit})'
        for entry in search_result.scan():
            try:
                self.data[entry.ip]
            except KeyError:
                # use list to keep order
                self.data[entry.ip] = {'hostnames': [], 'ports': []}
            # filter duplicates
            pp = '{}/{}'.format(entry.port, entry.protocol)
            if pp not in self.data[entry.ip]['ports']:
                self.data[entry.ip]['ports'].append(pp)
            try:
                if entry.hostname not in self.data[entry.ip]['hostnames']:
                    self.data[entry.ip]['hostnames'].append(entry.hostname)
            except AttributeError:
                pass

            try:
                try:
                    self.plugins[entry.pluginID]
                except KeyError:
                    self.plugins[entry.pluginID] = pline.format(pid=entry.pluginID, pname=entry.pluginName,
                                                                crit=entry.risk_factor)
            except AttributeError:
                pass

    def get_plugin_output(self):
        output = list(self.plugins.values())
        output.append('\n')
        return output

    def get_data_output(self):
        output = []
        for ip, hn_proto_port in self.data.items():
            hn_out = ''
            if hn_proto_port['hostnames']:
                hn_out = '({})'.format(', '.join(hn_proto_port['hostnames']))
            output.append('{} {}: {}'.format(ip, hn_out, ', '.join(hn_proto_port['ports'])))

        return output

    def render(self, search_result):
        self.get_data(search_result)
        output = self.get_plugin_output()
        output.extend(self.get_data_output())

        return output
