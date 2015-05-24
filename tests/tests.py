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
    time.sleep(0.01)
    return r


def json_get(url):
    r = requests.get(url,
                     headers={'content-type': 'application/json'})
    assert r.status_code == 200
    time.sleep(0.01)
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


def get_number_entries(api):
    r = json_get(api)
    return int(r["num_results"])
    

def check_sanity_suggestion_api():
    """ sanity-check suggestions API """
    api = TEST_API_SUGGESTIONS
    suggestion = {'content': 'blah blah test content'}
    n = get_number_entries(api)
    json_post(api, suggestion)
    assert get_number_entries(api) == n + 1


def schedule_robotask(url, priority):
    task = {'url': url, 'priority': priority}
    json_post(TEST_API_ROBOTASK, task)


def check_sanity_robotask_api():
    """ sanity-check robotask API """
    api = TEST_API_ROBOTASK
    n = get_number_entries(api)
    schedule_robotask("https://andymartin.cc", 5)
    assert get_number_entries(api) == n + 1
     

def check_sanity_webpage_pageview_script_api():
    """ sanity-check webpage, pageview, script APIs """
    n_webpages = get_number_entries(TEST_API_WEBPAGE)
    n_pageviews = get_number_entries(TEST_API_PAGEVIEW)
    n_scripts = get_number_entries(TEST_API_SCRIPT)

    webpage = {"id": "b0852f543b380fd1515112b0a4943cd4ab890d476698598e6b98357784901d1d",
               "url": "https://scriptobservatory.org/",
               "pageviews": [{'date': 888888888,
                             'scripts': [{'url': 'https://scriptobservatory.org/test.js',
                                         'hash': '274f2ba69eb1b2369d0bcc01969f290b644c7d22b84a99d4d13287f65bdc576a'}]
                            }]
              }
    
    json_post(TEST_API_WEBPAGE, webpage)
    
    assert get_number_entries(TEST_API_WEBPAGE) == n_webpages + 1
    assert get_number_entries(TEST_API_PAGEVIEW) == n_pageviews + 1
    assert get_number_entries(TEST_API_SCRIPT) == n_scripts + 1


def wait_for_robotask_to_be_emptied(timeout):
    """ keep polling the robotask API until it's empty, assert-ing False if *timeout* reached """
    initial_t = time.time()
    while get_number_entries(TEST_API_ROBOTASK) != 0:
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to clear out robotask API!
        time.sleep(timeout/5)


def wait_for_additions_to_webpage_api(webpage_entries, timeout):
    """ keep polling the webpage API until there are *webpage_entries* entries, assert-ing False if *timeout* is reached """
    initial_t = time.time()
    while get_number_entries(TEST_API_WEBPAGE) != webpage_entries:
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to increase size of webpage API!
        time.sleep(timeout/10)



def test_all():
    logging.basicConfig(level=logging.WARN)
    backend = launch_backend()


    # Test that all APIs are up and empty:
    assert get_number_entries(TEST_API_WEBPAGE) == 0
    assert get_number_entries(TEST_API_PAGEVIEW) == 0
    assert get_number_entries(TEST_API_SCRIPT) == 0
    assert get_number_entries(TEST_API_ROBOTASK) == 0
    assert get_number_entries(TEST_API_SUGGESTIONS) == 0
    

    # Do a quick sanity check that they're taking POSTs correctly:
    check_sanity_suggestion_api()
    check_sanity_robotask_api()
    check_sanity_webpage_pageview_script_api()


    # Test to see if the robo-browser empties the robotask API and adds to the webpage API:
    initial_n_webpages = get_number_entries(TEST_API_WEBPAGE)
    robobrowser = launch_robobrowser()
    wait_for_robotask_to_be_emptied(12)
    wait_for_additions_to_webpage_api(initial_n_webpages + 1, 60)


    # Submit a test pages to the robotask API & verify it's correctly recorded:
    initial_n_webpages = get_number_entries(TEST_API_WEBPAGE)
    schedule_robotask("https://andymartin.cc/test-pages/simple.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-link.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html", 5)
    wait_for_robotask_to_be_emptied(120)
    wait_for_additions_to_webpage_api(initial_n_webpages + 4, 60)


    # We're done!
    robobrowser.terminate()
    backend.terminate()

