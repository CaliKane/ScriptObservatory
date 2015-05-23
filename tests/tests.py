#!/usr/bin/env python3
#
# This is our first attempt at an automated test suite for ScriptObservatory. 
#
# For now, everything will be in one file and triggered with 'nose'. Eventually, it
# can be made more modular.
#
# In some ways, this will be the anti-unit test. 
# 
# Full end-to-end functionality will be tested: we'll start up the backend, test out 
# some basic API operations, and then use the robo-browser with the chrome extension 
# installed to test the accuracy of what's reported.
#
# To start, it will use a list of hard-coded webpages where we know what should be 
# reported. Eventually, it will generate a ton of webpages on the fly while also 
# verifying they get reported correctly, too.
#
# Because these tests involve multiple combinations of Python and JavaScript code, 
# I couldn't think of a perfectly clean way to do the testing. (For example, we want 
# to test the exact code that will eventually be run in production, but in production
# the extension will talk to https://scriptobservatory.org:443. The backend, however,
# relies on NGINX to terminate the TLS connection and actually expects HTTP traffic
# on port 8080.) 
#
# The compromises made to deal with these issues are described in more detail below.
#


import json
import logging
import os
import requests
import subprocess
import time


# relative paths from tests/ directory
PATH_TO_BACKEND = "../backend/backend.py"
PATH_TO_ROBO_BROWSER = "../robo-browser/robo-browser.py"
PATH_TO_CHROME_EXTENSION = "../chrome-extension/"

# set environment variables
FILEPATH = os.path.dirname(os.path.realpath(__file__))
os.environ["PATH_TO_EXTENSION"] = os.path.join(FILEPATH, PATH_TO_CHROME_EXTENSION)

TEST_API_SUGGESTIONS = "http://127.0.0.1:8080/api/suggestions"
TEST_API_ROBOTASK = "http://127.0.0.1:8080/api/robotask"


def launch_backend():
    """ launches backend.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching backend.py")
    s = subprocess.Popen(["python3.4", os.path.join(FILEPATH, PATH_TO_BACKEND)])
    time.sleep(1)
    return s


def launch_robobrowser():
    """ launches robo-browser.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching robo-browser.py")
    s = subprocess.Popen(["python3.4", os.path.join(FILEPATH, PATH_TO_ROBO_BROWSER)])
    time.sleep(1)
    return s


def check_api_up_and_empty(api_name):
    """ test that the *api_name* API is up """
    r = requests.get("http://127.0.0.1:8080/api/{0}".format(api_name),
                     headers={'content-type': 'application/json'})
    
    logging.warn("returned {0}: {1}".format(r.status_code, r.json()))
    assert r.status_code == 200
    response = r.json()
    assert int(response["num_results"]) == 0
    time.sleep(0.1)


def json_post(url, content):
    r = requests.post(url,
                      data=json.dumps(content),
                      headers={'content-type': 'application/json'})
    assert r.status_code == 201 
    return r


def json_get(url):
    r = requests.get(url,
                     headers={'content-type': 'application/json'})
    assert r.status_code == 200
    return r.json()


def test_all():
    logging.basicConfig(level=logging.WARN)

    backend = launch_backend()
    assert backend.poll() is None

    #robobrowser = launch_robobrowser()
    #assert robobrowser.poll() is None

    check_api_up_and_empty("webpage")
    check_api_up_and_empty("pageview")
    check_api_up_and_empty("script")
    check_api_up_and_empty("robotask")
    check_api_up_and_empty("suggestions")

    # test POST to suggestions API
    suggestion = {'content': 'blah blah test content'}
    response = json_post(TEST_API_SUGGESTIONS, suggestion)

    # test GET of new data on suggestions API 
    response = json_get(TEST_API_SUGGESTIONS)
    assert int(response["num_results"]) == 1


    backend.terminate()
    #robobrowser.terminate()


