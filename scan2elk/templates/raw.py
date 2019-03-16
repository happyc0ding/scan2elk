from pprint import pformat

from scan2elk.templates.base import TplBase


class TplRaw(TplBase):

    def __init__(self):
        super().__init__()

    def render(self, search_result):
        print('render')
        result = []
        for finding in search_result.scan():
            result.append(pformat(finding._d_, True))

        return result
