from collections import OrderedDict
import operator

from scan2elk.templates.base import TplBase


class TplNessusFinding(TplBase):

    def __init__(self):
        super().__init__()

    @staticmethod
    def _get_port_proto_str(ports, proto):
        pps = []
        for port in sorted(ports):
            pps.append('{}/{}'.format(port, proto))
        return pps

    def render(self, search_result):
        plugins = OrderedDict()
        findings = OrderedDict()
        line = '{pid}: {pname} ({crit})'
        for finding in search_result.scan():
            try:
                plugins[finding.pluginID]
            except KeyError:
                plugins[finding.pluginID] = {
                    'pstr': line.format(pid=finding.pluginID, pname=finding.pluginName,
                                        crit=finding.risk_factor),
                    'sev': finding.severity,
                }
            try:
                findings[finding.ip]
            except KeyError:
                findings[finding.ip] = {'ports_tcp': set(), 'ports_udp': set(), 'pids': set()}

            # tcp and udp ports only. WARNING: this will filter other protocols (obviously)
            if 'tcp' == finding.protocol.lower():
                findings[finding.ip]['ports_tcp'].add(finding.port)
            elif 'udp' == finding.protocol.lower():
                findings[finding.ip]['ports_udp'].add(finding.port)

            findings[finding.ip]['pids'].add(finding.pluginID)

        result = []
        for pstr_sev in plugins.values():
            result.append(pstr_sev['pstr'])
        result.append('')

        for ip, ports_pid in findings.items():
            result.append('{}: {}   # {}'.format(
                ip, ', '.join(self._get_port_proto_str(ports_pid['ports_tcp'], 'TCP') + self._get_port_proto_str(
                    ports_pid['ports_udp'], 'UDP')),
                ', '.join(sorted(map(str, ports_pid['pids'])))))

        return result
