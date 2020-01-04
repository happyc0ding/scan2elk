import logging

from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Q

from scan2elk.data_handler.data_handler import DataHandler

LOGGER = logging.getLogger(__name__)


class TestsslHandler(DataHandler):

    NAME = 'testssl'

    def __init__(self):
        super().__init__()

    def sanity_check(self):
        index_findings = self.index_names['finding']
        index_servicess = self.index_names['service']
        search_tls = Search(using=self._es, index=index_findings)
        search_service = Search(using=self._es, index=index_servicess)
        # get number of findings for finding "TLS1_2"
        num_tls = search_tls.query(Q({'query_string': {'query': 'name.raw:"TLS1_2"'}})).count()
        # get number of services
        num_host = search_service.query(Q({'query_string': {'query': '*'}})).count()
        # number of findings for "TLS1_2" must match number of detected services
        # TODO: does not work if multiple hosts in one file
        if num_tls != num_host:
            LOGGER.warning('Wrong testssl format detected. Found {} hosts and {} entries for finding "TLS1_2".'
                           ' Check the manual on how to use testssl'.format(num_host, num_tls))
