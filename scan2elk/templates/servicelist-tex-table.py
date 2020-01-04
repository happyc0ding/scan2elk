from scan2elk.templates.servicelist import TplServiceList


class TplServiceListTexTable(TplServiceList):

    def __init__(self):
        super().__init__()

    def get_data_output(self):
        output = []
        for ip, hn_proto_port in self.data.items():
            hn_out = ''
            if hn_proto_port['hostnames']:
                hn_out = '({})'.format(', '.join(hn_proto_port['hostnames']))
            output.append('{} {} & {} \\\\'.format(ip, hn_out, ', '.join(hn_proto_port['ports'])))

        return output
