#!/usr/bin/env python3
#
# This is the first attempt at an end-to-end test suite for ScriptObservatory. 
#
# For now, everything will be in one file and triggered with 'nose'. Eventually, it
# can be made more modular.
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
TEST_API_WEBPAGE = "http://127.0.0.1:8080/api/webpage"
TEST_API_PAGEVIEW = "http://127.0.0.1:8080/api/pageview"
TEST_API_SCRIPT = "http://127.0.0.1:8080/api/script"


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


def launch_backend():
    """ launches backend.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching backend.py")
    s = subprocess.Popen(["python3.4", os.path.join(FILEPATH, PATH_TO_BACKEND)])
    time.sleep(1)
    assert s.poll() is None
    return s


def launch_robobrowser():
    """ launches robo-browser.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching robo-browser.py")
    s = subprocess.Popen(["python3.4", os.path.join(FILEPATH, PATH_TO_ROBO_BROWSER)])
    time.sleep(1)
    assert s.poll() is None
    return s


def check_api_up_and_empty(api_name):
    """ test that the *api_name* API is up """
    r = requests.get("http://127.0.0.1:8080/api/{0}".format(api_name),
                     headers={'content-type': 'application/json'})
    
    logging.warn("returned {0}: {1}".format(r.status_code, r.json()))
    assert r.status_code == 200
    response = r.json()
    time.sleep(0.1)
    return int(response["num_results"]) == 0


def check_sanity_suggestion_api():
    """ sanity-check suggestions API """
    response = json_get(TEST_API_SUGGESTIONS)
    n_suggestions = int(response["num_results"])
    
    suggestion = {'content': 'blah blah test content'}
    json_post(TEST_API_SUGGESTIONS, suggestion)
    
    response = json_get(TEST_API_SUGGESTIONS)
    assert int(response["num_results"]) == n_suggestions + 1


def check_sanity_robotask_api():
    """ sanity-check robotask API """
    response = json_get(TEST_API_ROBOTASK)
    n_robotasks = int(response["num_results"])
    
    task = {'url': 'https://scriptobservatory.org/', 
            'priority': 10}
    json_post(TEST_API_ROBOTASK, task)
    
    response = json_get(TEST_API_ROBOTASK)
    assert int(response["num_results"]) == n_robotasks + 1
     

def check_sanity_webpage_pageview_script_api():
    """ sanity-check webpage, pageview, script APIs """
    response = json_get(TEST_API_WEBPAGE)
    n_webpages = int(response["num_results"])

    response = json_get(TEST_API_PAGEVIEW)
    n_pageviews = int(response["num_results"]) 

    response = json_get(TEST_API_SCRIPT)
    n_scripts = int(response["num_results"])

    webpage = {"id": "b0852f543b380fd1515112b0a4943cd4ab890d476698598e6b98357784901d1d",
               "url": "https://scriptobservatory.org/",
               "pageviews": [{'date': 888888888,
                             'scripts': [{'url': 'https://scriptobservatory.org/test.js',
                                         'hash': '274f2ba69eb1b2369d0bcc01969f290b644c7d22b84a99d4d13287f65bdc576a'}]
                            }]
              }
    json_post(TEST_API_WEBPAGE, webpage)
    
    response = json_get(TEST_API_WEBPAGE)
    assert int(response["num_results"]) == n_webpages + 1

    response = json_get(TEST_API_PAGEVIEW)
    assert int(response["num_results"]) == n_pageviews + 1

    response = json_get(TEST_API_SCRIPT)
    assert int(response["num_results"]) == n_scripts + 1


def test_all():
    logging.basicConfig(level=logging.WARN)

    backend = launch_backend()

    assert check_api_up_and_empty("webpage")
    assert check_api_up_and_empty("pageview")
    assert check_api_up_and_empty("script")
    assert check_api_up_and_empty("robotask")
    assert check_api_up_and_empty("suggestions")

    # TODO: make these delete the content they add
    check_sanity_suggestion_api()
    check_sanity_robotask_api()
    check_sanity_webpage_pageview_script_api()

    robobrowser = launch_robobrowser()

    initial_t = time.time()
    TIMEOUT = 15
    while not check_api_up_and_empty("robotask"):
        if time.time() - initial_t > TIMEOUT:
            assert False  # robobrowser failed to clear out robotask API!
        time.sleep(3)

    robobrowser.terminate()
    backend.terminate()

