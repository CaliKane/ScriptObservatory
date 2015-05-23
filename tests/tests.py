#!/usr/bin/env python3
#
# This is our first attempt at an automated test suite for ScriptObservatory. 
#
# For now, everything will be in one file and triggered with 'nose'. Eventually, it
# can be made more modular.
#
# In some ways, this will be the anti-unit test. 
# 
# Full end-to-end functionality will be tested: we'll spawn up the backend, test out 
# some basic API operations, and then use the robo-browser with the chrome extension 
# installed to test the accuracy of what's reported.
#
# To start, it will use a list of hard-coded webpages where we know what should be 
# reported. Eventually, it will generate a ton of webpages on the fly while also 
# verifying they get reported correctly, too.
#
# Because these tests are enormous and involved combinations of Python and JavaScript
# code, I couldn't think of a perfectly clean way to do the testing. (For example, 
# we want to run the exact code that will eventually run in production, but in production
# the extension will talk to https://scriptobservatory.org:443, whereas the backend
# relies on NGINX to terminate the TLS connection and actually expects HTTP traffic
# on port 8080.) 
#
# These kinds of compromises are described in more detail below.
#


import os
import logging
import requests
import subprocess
import time


def launch_backend():
    """ launches backend.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching backend.py")
    filepath = os.path.dirname(os.path.realpath(__file__))
    s = subprocess.Popen(["python3.4", "{0}".format(os.path.join(filepath, "../backend/backend.py"))])
    time.sleep(1)


def check_api_up(api_name):
    """ test that the *api_name* API is up """
    r = requests.get("http://127.0.0.1:8080/api/{0}".format(api_name),
                     headers={'content-type': 'application/json'})
    
    logging.warn("returned {0}: {1}".format(r.status_code, r.text))
    assert r.status_code == 200


def test_all():
    logging.basicConfig(level=logging.WARN)

    s = launch_backend()
    
    check_api_up("webpage")
    check_api_up("pageview")
    check_api_up("script")
    check_api_up("robotask")
    check_api_up("suggestions")

    """
    newperson = {'name': u'Lincoln', 'age': 23}
    r = requests.post('/api/person', data=json.dumps(newperson),
                      headers={'content-type': 'application/json'})
    r.status_code, r.headers['content-type'], r.data
    """
    
    s.terminate()


