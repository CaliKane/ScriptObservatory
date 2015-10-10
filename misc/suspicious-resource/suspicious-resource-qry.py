#!/usr/bin/env python3
#

import sys
from urllib.parse import urlparse

from backend.models import Webpage, Pageview, Resource


class Memoize:
    def __init__(self, f):
        self.f = f
        self.memo = {}
    def __call__(self, *args):
        if not args in self.memo:
            self.memo[args] = self.f(*args)
        return self.memo[args]

def get_root_domain(host):
    for tld in TLDS:
        if host.endswith(tld):
            host = host[:-len(tld)].split('.')[-1] + tld
            return host
    return host

def find_suspicious(pv_id):
    pageview = Pageview.query.filter(Pageview.id == pv_id).all()
	suspicious = []

	if not pageview:
		print('no pageview found with id {}'.format(pv_id))
	else:
        hostname = urlparse(pageview.url).netloc
        root_domain = get_root_domain(hostname)

        domains = [get_root_domain(urlparse(rsc.url).netloc) for rsc in pageview.resources]
 
        # dedup the list of domains and drop all empty values:
        domains = list(set(filter(lambda x: x, domains)))

        # remove any domains that are rooted in the WHITELIST or the current root_domain:
        suspicious = list(filter(lambda x: not any([x.endswith(y) for y in WHITELIST + [root_domain]]), domains))
        
    return suspicious


def run_suspicious_search(url):
    webpages = Webpage.query.filter(Webpage.url.like("%{}%".format(url))).all()
    
    results = {}
    for r in webpages:
        hostname = urlparse(r.url).netloc
        root_domain = get_root_domain(hostname)
        #print("{0} --> {1}".format(hostname, root_domain))

        domains = []
        for pv in r.pageviews:
            domains += [get_root_domain(urlparse(script.url).netloc) for script in pv.resources]
 
        # dedup the list of domains and drop all empty values:
        domains = list(set(filter(lambda x: x, domains)))

        # remove any domains that are rooted in the WHITELIST or the current root_domain:
        domains = list(filter(lambda x: not any([x.endswith(y) for y in WHITELIST + [root_domain]]), domains))
        
        if domains:
            results[r.url] = domains
   
    return results


if __name__ == "__main__":
    get_root_domain = Memoize(get_root_domain)

    WEBPAGE_FILE = sys.argv[1]
    WHITELIST_FILE = sys.argv[2]
    SORTED_TLD_FILE = sys.argv[3]

    TLDS = ['.' + line.strip() for line in open(SORTED_TLD_FILE, 'r')]
    WHITELIST = [line.strip() for line in open(WHITELIST_FILE, 'r')]

    for webpage in open(WEBPAGE_FILE, 'r'):
        results = run_suspicious_search(webpage.strip())
        
        for k in results.keys():
            if results[k]:
                print("{0}: {1}".format(k, results[k]))
