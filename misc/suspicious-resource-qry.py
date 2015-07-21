#!/usr/bin/env python3
#

import sys

from urllib.parse import urlparse

from backend.models import Webpage, Pageview, Script


WEBPAGE_FILE = sys.argv[1]
WHITELIST_FILE = sys.argv[2]


def run_suspicious_search(url):
    webpages = Webpage.query.filter(Webpage.url.like("%{}%".format(url))).all()
    
    results = {}
    for r in webpages:
        # TODO: fix this root-domain parsing
        hostname = urlparse(r.url).netloc.split('.')
        hostname = ".".join(len(hostname[-2]) < 4 and hostname[-3:] or hostname[-2:])

        domains = []
        for pv in r.pageviews:
            domains += [urlparse(script.url).netloc for script in pv.scripts]
            
        domains = list(set(filter(lambda x: x, domains)))

        domains = list(filter(lambda x: not any([x.endswith(y) for y in WHITELIST + [hostname]]), domains))
        
        if domains:
            results[r.url] = domains
   
    return results


WHITELIST = []
for line in open(WHITELIST_FILE, 'r'):
    WHITELIST.append(line.strip())

for webpage in open(WEBPAGE_FILE, 'r'):
    out = run_suspicious_search(webpage.strip())
    
    for k in out.keys():
        if out[k]:
            print("{0}: {1}".format(k, out[k]))
