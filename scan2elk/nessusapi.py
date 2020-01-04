import os
import logging
from http.client import HTTPSConnection
import getpass
import json
import ssl
from time import sleep
import tempfile

LOGGER = logging.getLogger(__name__)


class NessusAPI:

    def __init__(self, host, port, user, token_path='/tmp/scan2elk-nessus-token'):
        ssl_context = None
        # disable certificate check for localhost only
        if 'localhost' == host:
            ssl_context = ssl.SSLContext()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        self.client = HTTPSConnection(host, port, context=ssl_context)
        self.user = user
        self._token = ''
        self._token_path = token_path
        self._nessus_files = []
        self.read_token()

    @property
    def nessus_file_paths(self):
        return set([nfp.name for nfp in self._nessus_files])

    def read_token(self):
        try:
            with open(self._token_path, 'r') as read_token:
                self._token = read_token.read()
                LOGGER.info('Got existing token')
        except IOError:
            pass

    def write_token(self):
        with open(self._token_path, 'w') as write_token:
            write_token.write(self._token)
        # resrtict access. race condition for potential file access is acceptable
        os.chmod(self._token_path, 0o600)

    def _do_request(self, path, params=None, method='POST', is_auth_request=False, decode_json=True, is_nested=False):
        LOGGER.debug('Triggering request to: {}'.format(path))
        if params is not None:
            params = json.dumps(params)
        headers = {'Content-Type': 'application/json'}
        # prevent auth request loop
        if not is_auth_request and not self._token:
            self.authorize()
        # append token if available
        if self._token:
            headers['X-Cookie'] = 'token={}'.format(self._token)

        self.client.request(method, path, params, headers)
        data = self.client.getresponse().read()
        if decode_json:
            data = json.loads(data)
            try:
                if not is_auth_request and 'Invalid Credentials' == data['error']:
                    LOGGER.info('Credentials are not valid, triggering re-authentication...')
                    self.authorize()
                    # do request again
                    if not is_nested:
                        LOGGER.info('Repeating request')
                        data = self._do_request(path, params, method, is_auth_request, decode_json, True)
            except KeyError:
                pass

        return data

    def authorize(self):
        LOGGER.info('Authenticating with user: {}'.format(self.user))
        self._token = ''
        # get password via command line
        params = {'username': self.user, 'password': getpass.getpass()}
        response = self._do_request('/session', params, is_auth_request=True)
        try:
            self._token = response['token']
            self.write_token()
        except KeyError:
            LOGGER.error('Authentication failed with response: {}'.format(response))
            exit(0)
        else:
            LOGGER.info('Authentication done. Token: {}...'.format(self._token[0:-10]))

    def get_scan_ids(self, names):
        scan_ids = set()
        folders = self._do_request('/folders', method='GET')['folders']
        scans = self._do_request('/scans', method='GET')['scans']

        for scan in scans:
            if scan['name'] in names:
                # get folder name
                fname = [f for f in folders if f['id'] == scan['folder_id']][0]['name']
                LOGGER.info('Found nessus scan "{}" in folder "{}"'.format(scan['name'], fname))
                scan_ids.add(scan['id'])

        return scan_ids

    def download_exports(self, names):
        scan_ids = self.get_scan_ids(names)
        for scan_id in scan_ids:
            self._do_request('/scans/{}/export/formats?schedule_id={}'.format(scan_id, scan_id), method='GET')
            file_data = self._do_request('/scans/{}/export'.format(scan_id), {'format': 'nessus'})
            file_token = file_data['token']
            # wait up to ~30 seconds for the export to become ready
            max_tries = 15
            for i in range(1, max_tries):
                LOGGER.info('Waiting for export to become ready... (try {}/{})'.format(i, max_tries))
                status = self._do_request('/tokens/{}/status'.format(file_token), method='GET')
                if 'ready' == status['status']:
                    break
                sleep(1.5)
            LOGGER.info('Downloading export...')
            nessus_xml = self._do_request('/tokens/{}/download'.format(file_token), method='GET', decode_json=False)
            LOGGER.info('Trying to write temporary nessus file')
            tmp_file = tempfile.NamedTemporaryFile('wb', dir='/tmp', prefix='scan2elk-', suffix='.nessus')
            tmp_file.write(nessus_xml)
            LOGGER.info('Wrote to: "{}"'.format(tmp_file.name))
            self._nessus_files.append(tmp_file)

    def close_tmp_files(self):
        LOGGER.info('Deleting temporary nessus files')
        for nf in self._nessus_files:
            nf.close()
