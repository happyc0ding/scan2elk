import logging
import os

from elasticsearch import Elasticsearch, helpers
import oyaml as yaml


LOGGER = logging.getLogger(__name__)


class DataHandler(object):

    NAME = 'to be overwritten in child'

    base_mapping_certificate = {}
    base_mapping_cipher = {}
    base_mapping_finding = {}
    base_mapping_host = {}
    base_mapping_service = {}

    base_mapping = {}
    mapping_settings = {}

    def __init__(self):
        super().__init__()
        self.root_path = os.path.realpath(os.path.join(os.path.dirname(__file__), os.path.pardir))
        self.bulk_size = 1200
        self.index_names = {}
        self.index_types = ['finding', 'host', 'certificate', 'cipher', 'service']
        self.log_data_inserts = False

        with open(os.path.join(self.root_path, 'config', 'db.yaml'), 'r') as conf_file:
            config = yaml.safe_load(conf_file)
        self._es = Elasticsearch(host=config['host'], port=config['port'])

        # init settings and base mapping once
        if len(self.base_mapping) < 1:
            with open(os.path.join(self.root_path, 'config', 'mappings', 'settings.yaml'), 'r') as settings_file:
                self.mapping_settings = yaml.safe_load(settings_file)
            with open(os.path.join(self.root_path, 'config', 'mappings', 'base.yaml'), 'r') as base_file:
                self.base_mapping = yaml.safe_load(base_file)

        for index in self.index_types:
            # all specific base mappings only have to be initialized once
            # -> if one is not empty we cancel
            if len(getattr(self, 'base_mapping_{}'.format(index))) > 0:
                break

            file_path = os.path.join(self.root_path, 'config', 'mappings', '{}.yaml'.format(index))
            try:
                with open(file_path, 'r') as conf_file:
                    conf = yaml.safe_load(conf_file)
                    # empty config file
                    if conf is None:
                        LOGGER.debug('Empty config file: {}'.format(file_path))
                        conf = {}
                    # i.e. self.base_mapping_finding
                    setattr(self, 'base_mapping_{}'.format(index), conf)
            except IOError:
                LOGGER.exception('Error opening config file: {}'.format(file_path))
                raise

        self.certificate_mapping = {**self.base_mapping, **self.base_mapping_certificate,
                                    **self._load_mapping_config('certificate')}
        self.cipher_mapping = {**self.base_mapping, **self.base_mapping_cipher, **self._load_mapping_config('cipher')}
        self.finding_mapping = {**self.base_mapping, **self.base_mapping_finding,
                                **self._load_mapping_config('finding')}
        self.host_mapping = {**self.base_mapping, **self.base_mapping_host, **self._load_mapping_config('host')}
        self.service_mapping = {**self.base_mapping, **self.base_mapping_service,
                                **self._load_mapping_config('service')}

    def _load_mapping_config(self, file_name, ignore_error=False):
        conf = {}
        file_path = os.path.join(self.root_path, 'config', 'mappings', self.NAME, '{}.yaml'.format(file_name))
        try:
            with open(file_path, 'r') as conf_file:
                conf = yaml.safe_load(conf_file)
                # empty config file
                if conf is None:
                    LOGGER.debug('Empty config file: {}'.format(file_path))
                    conf = {}
        except IOError:
            if not ignore_error:
                LOGGER.exception('Error opening config file: {}'.format(file_path))
                raise
            LOGGER.debug('Cannot open config file: {}'.format(file_path))

        return conf

    # def init_indices(self, indices):
    #     for index, mapping in indices:
    #         self.init_index(index, mapping)
        #self._es.indices.put_mapping(index=index, doc_type=self.doctype, body={'properties': mapping})

    def create_index(self, name, index, mapping):
        self.index_names[name] = index
        self._es.indices.delete(index=index, ignore=[404])
        self._es.indices.create(
            index=index,
            body={
                'settings': self.mapping_settings,
                'mappings': {
                    index: {
                        'properties': mapping
                    }
                }
            }
        )

    def process_findings(self, findings):
        LOGGER.info('Processing findings')
        self._process_data(findings, self.index_names['finding'])

    def process_hosts(self, hosts):
        LOGGER.info('Processing hosts')
        self._process_data(hosts, self.index_names['host'])

    def process_certificates(self, certificates):
        LOGGER.info('Processing certificates')
        self._process_data(certificates, self.index_names['certificate'])

    def process_ciphers(self, ciphers):
        LOGGER.info('Processing ciphers')
        self._process_data(ciphers, self.index_names['cipher'])

    def process_services(self, services):
        LOGGER.info('Processing services')
        self._process_data(services, self.index_names['service'])

    def _process_data(self, data, index):
        bulk_data = []

        for entry in data:
            # also set "_id" manually in order to prevent duplicates
            # -> the id field is unique and shoult not exist more than once
            bulk_data.append({
                'index': {
                    '_type': index,
                    '_id': entry['id'],
                }
            })
            bulk_data.append(entry)
            if self.log_data_inserts:
                LOGGER.debug(sorted(entry.items()))

            # write to db
            if len(bulk_data) >= self.bulk_size:
                self._bulk_insert(index, bulk_data)
                bulk_data = []
        # insert the rest of the data
        self._bulk_insert(index, bulk_data)
        # refresh index
        self._es.indices.refresh(index=index)

    def _bulk_insert(self, index, bulk_data):
        if len(bulk_data) > 0:
            LOGGER.info('Writing {} entries to index: {}'.format(len(bulk_data), index))
            bulk_res = self._es.bulk(index=index, body=bulk_data, refresh=False)
            try:
                if bulk_res['errors']:
                    LOGGER.error('Error while inserting data')
                    LOGGER.error(bulk_res['items'][0]['index']['error'])
                    #LOGGER.error(bulk_data)
                    raise Exception('Error while inserting into db')
            except KeyError:
                pass

    def sanity_check(self):
        return
