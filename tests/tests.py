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

TEST_BASE_URL = "http://127.0.0.1:8080"
TEST_SUGGESTIONS_API = "http://127.0.0.1:8080/api/suggestions"
TEST_ROBOTASK_API = "http://127.0.0.1:8080/api/robotask"
TEST_WEBPAGE_API = "http://127.0.0.1:8080/api/webpage"
TEST_PAGEVIEW_API = "http://127.0.0.1:8080/api/pageview"
TEST_SCRIPT_API = "http://127.0.0.1:8080/api/script"


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
    api = TEST_SUGGESTIONS_API
    suggestion = {'content': 'blah blah test content'}
    n = get_number_entries(api)
    json_post(api, suggestion)
    assert get_number_entries(api) == n + 1


def schedule_robotask(url, priority):
    task = {'url': url, 'priority': priority}
    json_post(TEST_ROBOTASK_API, task)


def check_sanity_robotask_api():
    """ sanity-check robotask API """
    api = TEST_ROBOTASK_API
    n = get_number_entries(api)
    schedule_robotask("https://andymartin.cc", 5)
    assert get_number_entries(api) == n + 1
     

def check_sanity_webpage_pageview_script_api():
    """ sanity-check webpage, pageview, script APIs """
    n_webpages = get_number_entries(TEST_WEBPAGE_API)
    n_pageviews = get_number_entries(TEST_PAGEVIEW_API)
    n_scripts = get_number_entries(TEST_SCRIPT_API)

    webpage = {"id": "b0852f543b380fd1515112b0a4943cd4ab890d476698598e6b98357784901d1d",
               "url": "https://scriptobservatory.org/",
               "pageviews": [{'date': 888888888,
                             'scripts': [{'url': 'https://scriptobservatory.org/test.js',
                                         'hash': '274f2ba69eb1b2369d0bcc01969f290b644c7d22b84a99d4d13287f65bdc576a'}]
                            }]
              }
    
    json_post(TEST_WEBPAGE_API, webpage)
    
    assert get_number_entries(TEST_WEBPAGE_API) == n_webpages + 1
    assert get_number_entries(TEST_PAGEVIEW_API) == n_pageviews + 1
    assert get_number_entries(TEST_SCRIPT_API) == n_scripts + 1


def wait_for_robotask_to_be_emptied(timeout):
    """ keep polling the robotask API until it's empty, assert-ing False if *timeout* reached """
    initial_t = time.time()
    while get_number_entries(TEST_ROBOTASK_API) != 0:
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to clear out robotask API!
        time.sleep(timeout/5)


def wait_for_additions_to_webpage_api(webpage_entries, timeout):
    """ keep polling the webpage API until there are *webpage_entries* entries, assert-ing False if *timeout* is reached """
    initial_t = time.time()
    while get_number_entries(TEST_WEBPAGE_API) != webpage_entries:
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to increase size of webpage API!
        time.sleep(timeout/10)

    
def check_search_data(url, expected):
    r = json_get("{0}/search?url={1}".format(TEST_BASE_URL, url))
    print(url)
    print(r)
    print(ordered(r))
    assert ordered(r) == ordered(expected)


def ordered(obj):
    """ 
    ordered(obj) recursively orders all elements within *obj* and sets all values assocaited with 
    'date' keys to zero (when we're checking a result with a known-good value, the dates will never 
    be correct).
    
    adapted from this post:
    https://stackoverflow.com/questions/25851183/how-to-compare-two-json-objects-with-the-same-elements-in-a-different-order-equa 
    """
    if isinstance(obj, dict):
        if 'date' in obj.keys(): obj['date'] = 0
        return sorted((k, ordered(v)) for k, v in obj.items())
    elif isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj



def test_all():
    logging.basicConfig(level=logging.WARN)
    backend = launch_backend()


    # Test that all APIs are up and empty:
    assert get_number_entries(TEST_WEBPAGE_API) == 0
    assert get_number_entries(TEST_PAGEVIEW_API) == 0
    assert get_number_entries(TEST_SCRIPT_API) == 0
    assert get_number_entries(TEST_ROBOTASK_API) == 0
    assert get_number_entries(TEST_SUGGESTIONS_API) == 0
    

    # Do a quick sanity check that they're taking POSTs correctly:
    check_sanity_suggestion_api()
    check_sanity_robotask_api()
    check_sanity_webpage_pageview_script_api()


    # Test to see if the robo-browser empties the robotask API and adds to the webpage API:
    initial_n_webpages = get_number_entries(TEST_WEBPAGE_API)
    robobrowser = launch_robobrowser()
    wait_for_robotask_to_be_emptied(12)
    wait_for_additions_to_webpage_api(initial_n_webpages + 1, 60)


    # Submit a test pages to the robotask API & verify it's correctly recorded:
    initial_n_webpages = get_number_entries(TEST_WEBPAGE_API)
    schedule_robotask("https://andymartin.cc/test-pages/simple.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-link.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html", 5)
    
    wait_for_robotask_to_be_emptied(120)
    wait_for_additions_to_webpage_api(initial_n_webpages + 4, 60)
 
    url = "https://andymartin.cc/test-pages/simple.html"
    correct = {'objects': [{'pageviews': [{'date': 1432517947093, 'scripts': []}], 'id': 'adc0ef3d09029497ef790606011ab866af526fa6e034244c8b311fd31a0ef42d', 'url': 'https://andymartin.cc/test-pages/simple.html'}]}
    check_search_data(url, correct)
    
    url = "https://andymartin.cc/test-pages/one-script-by-inline.html"
    correct = {'objects': [{'id': 'a0f33bba1eb36b4bbb9cef89a7f72e015fe5bf8cdc957fb6a1f0aee130f71e79', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline.html', 'pageviews': [{'scripts': [{'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}], 'date': 1432518282712}]}]}
    check_search_data(url, correct)

    url = "https://andymartin.cc/test-pages/one-script-by-link.html"
    correct = {'objects': [{'pageviews': [{'date': 1432517971394, 'scripts': [{'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world.js'}]}], 'id': 'b81cfef4f4c8515c985de28f290ca1b4577e7500bb166b26b2a3e6eecebe3363', 'url': 'https://andymartin.cc/test-pages/one-script-by-link.html'}]}
    check_search_data(url, correct)
 
    url = "https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html"
    correct = {'objects': [{'pageviews': [{'scripts': [{'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html', 'id': 'bcbd228cb9bbd1128c50e4f3bde5806820f056777574dc026e0b500023436228'}]}
    check_search_data(url, correct)
 
    
    # We're done!
    robobrowser.terminate()
    backend.terminate()


