#!/usr/bin/env python3

import os
import argparse
import logging
import re

from elasticsearch.exceptions import ConnectionError

from vulnscan_parser.parser.nessus.xml import NessusParserXML
from vulnscan_parser.parser.testssl.json import TestsslParserJson
from vulnscan_parser.parser.sslyze.xml import SslyzeParserXML
from vulnscan_parser.parser.nmap.xml import NmapParserXML
from vulnscan_parser.parser.sslscan.xml import SSLScanParserXML

from scan2elk.data_handler.testssl import TestsslHandler
from scan2elk.data_handler.sslyze import SslyzeHandler
from scan2elk.data_handler.nessus import NessusHandler
from scan2elk.data_handler.nmap import NmapHandler
from scan2elk.data_handler.sslscan import SslscanHandler

__author__ = 'happyc0ding'
__version__ = '0.1'
__status__ = 'Development'

logging.basicConfig(level=logging.INFO)
logging.getLogger('elasticsearch').setLevel(logging.ERROR)


def process(elk_handler, parser):
    elk_handler.process_findings((finding.to_serializable_dict() for finding in parser.findings.values()))
    elk_handler.process_certificates((cert.to_serializable_dict() for cert in parser.certificates.values()))
    elk_handler.process_ciphers((cipher.to_serializable_dict() for cipher in parser.ciphers.values()))
    elk_handler.process_hosts((host.to_serializable_dict() for host in parser.hosts.values()))
    elk_handler.process_services((service.to_serializable_dict() for service in parser.services.values()))
    elk_handler.sanity_check()
    # save memory
    parser.clear()


if '__main__' == __name__:

    LOGGER = logging.getLogger(__name__)
    LOGGER.setLevel(logging.DEBUG)
    IGNORED_FILE_EXTENSIONS = {
        'nmap',
        'gnmap',
        'stderr',
        'stdout',
        'png',
        'txt',
        'sqlite',
    }

    arg_parser = argparse.ArgumentParser(description='Scan2elk')
    arg_parser.add_argument('-dir', action='store', nargs='+', help='Directories to parse', required=True)
    arg_parser.add_argument('-project', action='store', help='Project name', required=True)
    arg_parser.add_argument('-noduplicates', action='store_true', help='Do not save duplicate findings')
    arg_parser.add_argument('-ignore-file-ext', action='store', nargs='+', default=[],
                            help='List of file extensions to ignore (space or comma separated), i.e. "docx pdf ini"')
    arg_parser.add_argument('-include-file-ext', action='store', nargs='+', default=[],
                            help='List of file extensions to include (space or comma separated), i.e. "docx pdf ini"'
                            'All other file extensions will be ignored!')
    arg_parser.add_argument('-debug', action='store_true', help='Set logging to debug')
    arg_parser.add_argument('-debugelk', action='store_true', help='Set elasticsearch logging to debug')
    args = arg_parser.parse_args()

    project_name = args.project
    # TODO: create function for this
    ignored_file_ext = IGNORED_FILE_EXTENSIONS.copy()
    for igf in args.ignore_file_ext:
        igf = igf.strip(' ')
        if ',' in igf:
            for x in igf.split(','):
                ignored_file_ext.add(x.strip(' '))
        else:
            ignored_file_ext.add(igf)

    included_file_ext = set()
    for igf in args.include_file_ext:
        igf = igf.strip(' ')
        if ',' in igf:
            for x in igf.split(','):
                included_file_ext.add(x.strip(' '))
        else:
            included_file_ext.add(igf)

    if args.debug:
        logging.getLogger('scan2elk').setLevel(logging.DEBUG)
    if args.debugelk:
        logging.getLogger('elasticsearch').setLevel(logging.DEBUG)

    if not re.match('^[\w_-]+$', project_name):
        print('No special chars in project name, please')
        exit(1)

    parsers = {
        'nmap': NmapParserXML(),
        'nessus': NessusParserXML(),
        'testssl': TestsslParserJson(),
        'sslyze': SslyzeParserXML(),
        'sslscan': SSLScanParserXML(),
    }

    add_duplicates = not args.noduplicates

    data_handlers = {
        'nmap': NmapHandler(),
        'nessus': NessusHandler(),
        'testssl': TestsslHandler(),
        'sslyze': SslyzeHandler(),
        'sslscan': SslscanHandler(),
    }

    result_file_list = {k: set() for k in parsers.keys()}
    for directory in args.dir:
        # walk dir recursively
        for root, dirs, files in os.walk(os.path.realpath(directory)):
            for the_file in files:
                file_ext = os.path.splitext(the_file)[1][1:]

                # check for ingnored files
                if file_ext.lower() in ignored_file_ext or\
                        (included_file_ext and file_ext not in included_file_ext):
                    continue

                full_path = os.path.realpath(os.path.join(root, the_file))
                if the_file.endswith('.nessus'):
                    result_file_list['nessus'].add(full_path)
                    continue
                elif the_file.endswith('.xml'):
                    if the_file.startswith('sslyze'):
                        result_file_list['sslyze'].add(full_path)
                        continue
                    elif the_file.startswith('nmap'):
                        result_file_list['nmap'].add(full_path)
                        continue
                    elif the_file.lower().startswith('sslscan'):
                        result_file_list['sslscan'].add(full_path)
                    # all except nikto
                    elif the_file.startswith('nikto'):
                        continue
                # TODO: sslyze json?
                elif the_file.endswith('.json'):
                    result_file_list['testssl'].add(full_path)
                    continue

                # check if one of the parsers recognizes the file
                for pname, parser in parsers.items():
                    if parser.is_valid_file(full_path):
                        result_file_list[pname].add(full_path)
                        break
                else:
                    LOGGER.warning('Unknown file type: {}'.format(full_path))

                # elif the_file.endswith('.pem') or (the_file.startswith('openssl_') and the_file.endswith('.stdout')):
                #     result_file_list['openssl'].add(full_path)
                #
                # elif 'result.sqlite' == the_file:
                #     result_file_list['sdc'].add(full_path)

    try:
        for tool, handler in data_handlers.items():
            parsers[tool].add_duplicates = add_duplicates
            # init indices
            # index_type = finding, host, ...
            for index_type in handler.index_types:
                index = '{}_{}_{}'.format(index_type, tool, project_name)
                mapping = getattr(handler, '{}_mapping'.format(index_type))
                # LOGGER.info('init index: {} {}'.format(index, mapping))
                handler.create_index(index_type, index, mapping)
            # parse files
            for filepath in result_file_list[tool]:
                parser = parsers[tool]
                # sanity check
                if not parser.is_valid_file(filepath):
                    LOGGER.error('Invalid content in file {} for parser {}'.format(filepath, tool))
                    continue

                parser.parse(filepath)

                # check if any of the results exceeds bulk size
                if any(len(x) > handler.bulk_size for x in (parser.findings, parser.certificates, parser.ciphers,
                                                            parser.hosts, parser.services)):
                    process(handler, parser)
            # process remaining
            process(handler, parsers[tool])
    except ConnectionError:
        LOGGER.error('Unable to connect to elasticsearch')


