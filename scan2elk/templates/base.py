import re


class TplBase:

    LATEX_SUBS = (
        (re.compile(r'\\'), r'\\textbackslash'),
        (re.compile(r'([{}_#%&$])'), r'\\\1'),
        (re.compile(r'~'), r'\~{}'),
        (re.compile(r'\^'), r'\^{}'),
        (re.compile(r'"'), r"''"),
        #(re.compile(r'\.\.\.+'), r'\\ldots'),
    )

    def __init__(self):
        pass

    def render(self, search_result):
        return ['Not implemented']

    def escape_tex(self, text):
        newval = text
        for pattern, replacement in self.LATEX_SUBS:
            newval = pattern.sub(replacement, newval)
        return newval
