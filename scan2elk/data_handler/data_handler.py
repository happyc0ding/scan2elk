import logging
import os

from elasticsearch import Elasticsearch, helpers
import oyaml as yaml


LOGGER = logging.getLogger(__name__)


class DataHandler(object):

    NAME = 'to be overwritten in child'

    def __init__(self, ignoremappings=False):
        super().__init__()
        self.root_path = os.path.realpath(os.path.join(os.path.dirname(__file__), os.path.pardir))
        self.bulk_size = 1200
        self.index_names = {}
        self.index_types = ['finding', 'host', 'certificate', 'cipher', 'service']
        self.log_data_inserts = False

        self._es = None
        self.certificate_mapping = {}
        self.cipher_mapping = {}
        self.finding_mapping = {}
        self.host_mapping = {}
        self.service_mapping = {}

        self.base_mapping_certificate = {}
        self.base_mapping_cipher = {}
        self.base_mapping_finding = {}
        self.base_mapping_host = {}
        self.base_mapping_service = {}

        self.base_mapping = {}
        self.mapping_settings = {}

        self.xdg_config_home = ''
        try:
            self.xdg_config_home = os.environ['XDG_CONFIG_HOME']
        except KeyError:
            pass
        if not self.xdg_config_home:
            self.xdg_config_home = os.path.join(os.path.expanduser('~'), '.config', 'scan2elk')

        self.init_db()
        if not ignoremappings:
            self.init_mappings()

    def get_yaml_file(self, file_path, ignore_error=False):
        yaml_data = {}
        try:
            with open(file_path, 'r') as yaml_file:
                yaml_data = yaml.safe_load(yaml_file)
        except FileNotFoundError:
            if not ignore_error:
                LOGGER.exception('Error opening config file: {}'.format(file_path))
                raise
            LOGGER.debug('Cannot open config file: {}'.format(file_path))

        return yaml_data

    def _load_mapping_config(self, file_name, ignore_error=False):
        conf = {}
        config_path = os.path.join(self.root_path, 'config', 'mappings', self.NAME, '{}.yaml'.format(file_name))
        xdg_config_path = os.path.join(self.xdg_config_home, 'mappings', self.NAME, '{}.yaml'.format(file_name))

        for file_path in (config_path, xdg_config_path):
            yaml_conf = self.get_yaml_file(file_path, ignore_error)
            # empty config file
            if yaml_conf is not None:
                conf.update(yaml_conf)
            else:
                LOGGER.debug('Empty config file: {}'.format(file_path))
            # ignore error for custom files
            ignore_error = True

        return conf

    def init_db(self):
        config = {
            **self.get_yaml_file(os.path.join(self.root_path, 'config', 'db.yaml')),
            **self.get_yaml_file(os.path.join(self.xdg_config_home, 'db.yaml'), True)
        }
        self._es = Elasticsearch(host=config['host'], port=config['port'])

    def init_mappings(self):
        # init settings and base mapping once
        self.mapping_settings = {
            **self.get_yaml_file(os.path.join(self.root_path, 'config', 'mappings', 'settings.yaml')),
            **self.get_yaml_file(os.path.join(self.xdg_config_home, 'mappings', 'settings.yaml'), True)
        }
        self.base_mapping = {
            **self.get_yaml_file(os.path.join(self.root_path, 'config', 'mappings', 'base.yaml')),
            **self.get_yaml_file(os.path.join(self.xdg_config_home, 'mappings', 'base.yaml'), True)
        }

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

    def create_index(self, name, index, mapping):
        self.index_names[name] = index
        self._es.indices.delete(index=index, ignore=[404])

        self._es.indices.create(
            index=index,
            body={
                'settings': self.mapping_settings,
                'mappings': {
                    '_doc': {
                        'properties': mapping
                    }
                }
            },
            include_type_name=True
        )

    def delete_indices(self, project=None):
        indices = []
        for existing_index in self._es.indices.get('*').keys():
            # avoid deleting unrelated indices (not 100% safe though!)
            if project is None:
                do_delete = any(existing_index.startswith(x) for x in self.index_types)
            else:
                do_delete = existing_index.endswith(project)

            if do_delete:
                self._es.indices.delete(index=existing_index)
                indices.append(existing_index)
        if len(indices) > 0:
            print('Deleted indices: {}'.format(', '.join(sorted(indices))))

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
                    '_type': '_doc',
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
            LOGGER.info('Writing {} entries to index: {}'.format(int(len(bulk_data)/2), index))
            bulk_res = self._es.bulk(index=index, body=bulk_data, refresh=False)
            try:
                if bulk_res['errors']:
                    LOGGER.error('Error while inserting data')
                    LOGGER.error(bulk_res['items'][0]['index']['error'])
                    raise Exception('Error while inserting into db')
            except KeyError:
                pass

    def sanity_check(self):
        return
