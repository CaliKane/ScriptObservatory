#!/usr/bin/env python3
#

import re

from backend.models import Suggestions



def is_not_sha256(h, regex=re.compile(r'^[a-f0-9]{64}$').search):
    """ determine if a string *h* is a valid sha256 hash """
    return not bool(regex(h))


def is_not_inline_script(u):
    return 'inline_script_' not in u


if __name__ == '__main__':
    suggestions = [x.content for x in Suggestions.query.all()]

    print('have {} new suggestions'.format(len(suggestions)))

    suggestions = list(set(suggestions))

    print('{} are unique'.format(len(suggestions)))

    suggestions = list(filter(lambda x: is_not_sha256(x) and is_not_inline_script(x), suggestions))

    print('{} are not hashes/inline_script_s'.format(len(suggestions)))
 
    suggestions = list(filter(lambda x: 'http' in x.lower(), suggestions))

    print('{} have "http" in them'.format(len(suggestions)))

    for s in suggestions:
        print(s)


