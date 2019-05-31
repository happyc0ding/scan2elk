#!/usr/bin/env python3


import logging
from argparse import ArgumentParser
from pprint import pprint
import inspect
import importlib
import os

import cmd2
from elasticsearch.exceptions import ElasticsearchException
from elasticsearch import Elasticsearch
from elasticsearch_dsl import Search
from elasticsearch_dsl.query import Q

from scan2elk.templates.base import TplBase

#logging.basicConfig(level=logging.INFO)
#logging.getLogger('elasticsearch').setLevel(level=logging.INFO)


class Scan2ElkInteractive(cmd2.Cmd):

    def __init__(self):
        super().__init__()
        # set minimal prompt
        self.prompt = '> '
        # necessary due to problems with chars like '>' in search queries
        self.allow_redirection = False

        self.project_name = ''
        self.indices = set()
        self.es = Elasticsearch()
        self.existing_indices = set()
        self.template = None
        self.last_query = ''
        self.sort = []
        self.existing_fields = {}
        self.current_fields = set()
        self.refresh_indices_and_fields()

    @property
    def all_existing_fields(self):
        all_fields = set()
        for fields in self.existing_fields.values():
            all_fields |= fields

        return all_fields

    def refresh_indices_and_fields(self):
        for index in self.es.indices.get('*').keys():
            if not self.project_name or index.endswith('_{}'.format(self.project_name)):
                self.existing_indices.add(index)

        for mname, data in self.es.indices.get_mapping(','.join(self.existing_indices), pretty=True).items():
            try:
                self.existing_fields[mname]
            except KeyError:
                self.existing_fields[mname] = set()
            for prop in data['mappings']['properties']:
                self.existing_fields[mname].add(prop)
                self.all_existing_fields.add(prop)
    #
    # def postparsing_precmd(self, statement):
    #     if 'search' == statement.command:
    #         print(statement.args)
    #     return super().postparsing_precmd(statement)

    def onecmd(self, statement):
        if not self.project_name and statement.command not in ('setproject', 'showindices', 'quit', 'exit'):
            self.poutput('You have to set a project first. Check "setproject" command')
            return False

        return super().onecmd(statement)

    # noinspection PyUnusedLocal
    def do_showindices(self, args):
        self.poutput('Got available indices:')
        self.poutput(','.join(sorted(self.existing_indices)))

    showfields_parser = ArgumentParser(description='Show fields in all or selected indices')
    showfields_parser.add_argument('-indices', nargs='+', required=False, help='Indices to check')
    showfields_parser.add_argument('-fields', nargs='+', default=[], required=False,
                                   help='Search for fields containing "value" (lowercase)')

    @cmd2.with_argparser(showfields_parser)
    def do_showfields(self, args):
        indices = sorted(self.indices)
        if args.indices:
            indices = sorted(args.indices)
        if not indices:
            self.poutput('No indices selected')
        else:
            for index in indices:
                self.poutput('----------------------------------------------------------------------------------------')
                self.poutput('{}:'.format(index))
                self.poutput(','.join((i for i in self.existing_fields[index]
                                       if not args.fields or any(f in i.lower() for f in map(str.lower, args.fields)))))

    setproject_parser = ArgumentParser(description='Set project to use')
    setproject_parser.add_argument('project', nargs=1, help='Project name')

    @cmd2.with_argparser(setproject_parser)
    def do_setproject(self, args):
        self.project_name = args.project[0]
        self.refresh_indices_and_fields()

    setindices_parser = ArgumentParser(description='Set index/indices to search')
    setindices_parser.add_argument('indices', nargs='+', help='Space or comma separated list of indices')

    @cmd2.with_argparser(setindices_parser)
    def do_setindices(self, args):
        self.indices = set()
        self.current_fields = set()
        for index in args.indices:
            index = index.split(',')
            for index_name in index:
                if index_name in self.existing_indices:
                    self.indices.add(index_name)
                    self.current_fields |= self.existing_fields[index_name]
                else:
                    self.poutput('Unknown index: {}'.format(index_name))

    # noinspection PyUnusedLocal
    def complete_setindices(self, text, line, begidx, endidx):
        return [x for x in self.existing_indices if x.startswith(text) or not text]

    settemplate_parser = ArgumentParser(description='Set template for output')
    settemplate_parser.add_argument('tpl', nargs=1, help='Template')

    @cmd2.with_argparser(settemplate_parser)
    def do_settemplate(self, args):
        self.template = None
        tpl_name = args.tpl[0]
        try:
            template_mod = importlib.import_module('scan2elk.templates.{}'.format(tpl_name))
        except ModuleNotFoundError:
            self.poutput('Unknown template: {}'.format(tpl_name))
            return

        template_clazz = None
        # get class information
        for name, clazz in inspect.getmembers(template_mod):
            # make sure everything is as expected
            if 'TplBase' != name and name.startswith('Tpl') and inspect.isclass(clazz) and \
                    issubclass(clazz, TplBase):
                template_clazz = clazz

        if template_clazz:
            self.template = template_clazz()
        else:
            self.poutput('Unknown template: {}'.format(tpl_name))

    def complete_settemplate(self, text, line, begidx, endidx):
        tplpath = os.path.realpath(os.path.join(os.path.dirname(__file__), 'scan2elk', 'templates'))
        text = os.path.join(tplpath, text)
        all_files = [os.path.basename(f)[:-3] for f in self.path_complete(text, line, begidx, endidx)
                     if os.path.isfile(f) and f.endswith('.py')]
        # reset display due to using path_complete
        self.display_matches = []

        return [x for x in all_files if not x.startswith('_') and 'base.py' != x]

    def do_setsort(self, args):
        if not self.indices:
            self.poutput('Set indices first using setindices!')
            return

        self.sort = []
        for sort_fields in args.split(','):
            for sort in sort_fields.split(' '):
                if sort.lstrip('-') in self.all_existing_fields:
                    self.sort.append(sort)
                else:
                    self.poutput('Unknown field: '.format(sort))
        self.poutput('Set sorting to: {}'.format(','.join(self.sort)))

    # noinspection PyUnusedLocal
    def complete_setsort(self, text, line, begidx, endidx):
        return [x for x in self.existing_fields if x.startswith(text) or not text]

    # search_parser = ArgumentParser(description='Search in indices')
    # search_parser.add_argument('searchstr', nargs=1, action='store', help='Search string')
    #
    # @cmd2.with_argparser(search_parser)
    def do_search(self, statement):
        if not self.template:
            self.poutput('You have to choose a template using settemplate!')
            return
        if not self.indices:
            self.poutput('Set indices first using setindices!')
            return

        # use the raw statement here because chars like '>' might be used in the search, which would redirect
        # output otherwise -> find first space in "search my search parameters and stuff field:>0"
        self.last_query = statement.raw[statement.raw.find(' ')+1:]
        try:
            search = Search(using=self.es, index=','.join(self.indices))
            q = Q({'query_string': {'query': self.last_query}})
            if not self.sort:
                self.poutput('Querying db without sorting')
                result = search.query(q)
            else:
                sorting = ','.join(self.sort)
                self.poutput('Querying db with sorting: {}'.format(sorting))
                result = search.query(q).sort(*self.sort).params(preserve_order=True)

            self.poutput('\n'.join(self.template.render(result)))
        except ElasticsearchException:
            self.perror('Error while parsing query')
        self.poutput('Done.')

    # noinspection PyUnusedLocal
    def complete_search(self, text, line, begidx, endidx):
        self.allow_appended_space = False
        result = []
        if not text or (text and text[-1] not in (':', '<', '>')):
            # filter search, always ignore "patch_summary*"
            result = ['{}:'.format(x) for x in self.current_fields
                      if (not text or x.startswith(text)) and not x.startswith('patch_summary')]
        # remove ':' for matches
        self.display_matches = [x[:-1] for x in result]

        return result


if '__main__' == __name__:
    app = Scan2ElkInteractive()
    app.cmdloop()
