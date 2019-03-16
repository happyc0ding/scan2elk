#!/usr/bin/env python3

import argparse
from pprint import pprint

from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Q

if '__main__' == __name__:
    arg_parser = argparse.ArgumentParser(description='search helper, (c) happyc0ding')
    arg_parser.add_argument('-i', '--index', action='store', help='index to search in', required=True)
    arg_parser.add_argument('-d', '--doc_type', action='store', help='doc type to search in', default=None)
    arg_parser.add_argument('-s', '--search', action='store', help='search query', required=True)
    args = arg_parser.parse_args()

    index = args.index
    doc_type = args.doc_type

    es = Elasticsearch()
    search = Search(using=es, index=index, doc_type=doc_type)
    q = Q({'query_string': {'query': args.search}})
    res = search.query(q)

    for hit in res.scan():
        pprint(vars(hit))
        #print(hit.pluginID)
        #print(hit.pluginName)
        #print(hit.severity)
        #print(hit.risk_factor)
