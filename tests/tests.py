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


import hashlib
import html
import json
import logging
import os
import requests
import subprocess
import time


# relative paths from tests/ directory
PATH_TO_PROJ_ROOT = "../"
PATH_TO_BACKEND = "../runserver.py"
PATH_TO_ROBO_BROWSER = "../robo-browser/"
PATH_TO_CHROME_EXTENSION = "../chrome-extension/"

# set environment variables
FILEPATH = os.path.dirname(os.path.realpath(__file__))
os.environ["PATH_TO_EXTENSION"] = os.path.join(FILEPATH, PATH_TO_CHROME_EXTENSION)

# URL paths
TEST_BASE_URL = "http://127.0.0.1:8080"
TEST_SUGGESTIONS_API = "http://127.0.0.1:8080/api/suggestions"
TEST_ROBOTASK_API = "http://127.0.0.1:8080/api/robotask"
TEST_WEBPAGE_API = "http://127.0.0.1:8080/api/webpage"
TEST_PAGEVIEW_API = "http://127.0.0.1:8080/api/pageview"
TEST_RESOURCE_API = "http://127.0.0.1:8080/api/resource"
TEST_RESOURCE_CONTENT_API = "http://127.0.0.1:8080/api/resource-content"


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
    s = subprocess.Popen(["python3.4", os.path.join(FILEPATH, PATH_TO_BACKEND)], 
                         cwd=os.path.join(FILEPATH, PATH_TO_PROJ_ROOT))
    time.sleep(1)
    assert s.poll() is None
    return s


def launch_robobrowser():
    """ launches robo-browser.py and returns the subprocess handle so it can be later terminated """
    logging.warn("launching robo-browser.sh")
    s = subprocess.Popen(["bash", "./robo-browser.sh"],
                         cwd=os.path.join(FILEPATH, PATH_TO_ROBO_BROWSER))
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
    n_scripts = get_number_entries(TEST_RESOURCE_API)

    webpage = {"id": "b0852f543b380fd1515112b0a4943cd4ab890d476698598e6b98357784901d1d",
               "url": "https://scriptobservatory.org/",
               "pageviews": [{'resources': [{'url': 'https://scriptobservatory.org/test.js',
                                            'hash': '274f2ba69eb1b2369d0bcc01969f290b644c7d22b84a99d4d13287f65bdc576a'}]
                            }]
              }
    
    json_post(TEST_WEBPAGE_API, webpage)
    
    assert get_number_entries(TEST_WEBPAGE_API) == n_webpages + 1
    assert get_number_entries(TEST_PAGEVIEW_API) == n_pageviews + 1
    assert get_number_entries(TEST_RESOURCE_API) == n_scripts + 1


def wait_for_robotask_to_be_emptied(timeout):
    """ keep polling the robotask API until it's empty, assert-ing False if *timeout* reached """
    initial_t = time.time()
    while get_number_entries(TEST_ROBOTASK_API) != 0:
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to clear out robotask API!
        time.sleep(5)


def wait_for_additions_to_webpage_api(webpage_entries, timeout):
    """ keep polling the webpage API until there are *webpage_entries* entries, assert-ing False if *timeout* is reached """
    initial_t = time.time()
    n = get_number_entries(TEST_WEBPAGE_API)
    while n < webpage_entries:
        print("we have {0} entries, need {1} more".format(n, webpage_entries - n))
        if time.time() - initial_t > timeout:
            assert False  # robobrowser failed to increase size of webpage API!
        time.sleep(5)
        n = get_number_entries(TEST_WEBPAGE_API) 

    
def check_search_data(url, expected):
    r = json_get("{0}/api/search?url={1}".format(TEST_BASE_URL, url))
    
    correct = ordered(expected)
    output = ordered(r)
    print("expected: {0}\ngot:      {1}\n".format(correct, output))
    assert correct == output


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


def check_script_content(h):
    """ checks that /script-content/*h* exists on the server and that the hash is correct """
    url = "{0}?content=true&hashes={1}".format(TEST_RESOURCE_CONTENT_API, h)

    r = requests.get(url)
    assert r.status_code == 200

    script_content = json.loads(r.text)[h]
    script_content = html.unescape(script_content).encode('utf-8')

    sha256 = hashlib.sha256(script_content).hexdigest()
    print("expected: {0}\ngot:      {1}\n".format(h, sha256))
    assert sha256 == h


def test_all():
    logging.basicConfig(level=logging.WARN)
    backend = launch_backend()
    time.sleep(2) # give backend 2s to get ready

    # Test that all APIs are up and empty:
    assert get_number_entries(TEST_WEBPAGE_API) == 0
    assert get_number_entries(TEST_PAGEVIEW_API) == 0
    assert get_number_entries(TEST_RESOURCE_API) == 0
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
    schedule_robotask("https://andymartin.cc/test-pages/simple.html", 1)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline.html", 2)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-link.html", 3)
    schedule_robotask("https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html", 4)
    schedule_robotask("https://andymartin.cc/test-pages/iframe-simple.html", 5)
    schedule_robotask("https://andymartin.cc/test-pages/iframe-dropped.html", 6)
    schedule_robotask("https://andymartin.cc/test-pages/iframe-simple-nested.html", 7)
    schedule_robotask("https://andymartin.cc/test-pages/iframe-dropped-nested.html", 8)
    schedule_robotask("https://andymartin.cc/test-pages/redirect-inline.html", 9)  # this also creates a record for end.html
    schedule_robotask("https://andymartin.cc/test-pages/redirect-remote.html", 10) # this also creates a record for end.html
    schedule_robotask("https://andymartin.cc/test-pages/10-scripts.html", 11)
    schedule_robotask("https://andymartin.cc/test-pages/100-scripts.html", 12)
    wait_for_robotask_to_be_emptied(300)
    wait_for_additions_to_webpage_api(initial_n_webpages + 13, 60)  # +1 bc of extra for end.html
 
    url = "https://andymartin.cc/test-pages/simple.html"
    correct = {'objects': [{'pageviews': [{'resources': []}], 'id': 'adc0ef3d09029497ef790606011ab866af526fa6e034244c8b311fd31a0ef42d', 'url': 'https://andymartin.cc/test-pages/simple.html'}]}
    check_search_data(url, correct)
    
    url = "https://andymartin.cc/test-pages/one-script-by-inline.html"
    correct = {'objects': [{'id': 'a0f33bba1eb36b4bbb9cef89a7f72e015fe5bf8cdc957fb6a1f0aee130f71e79', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline.html', 'pageviews': [{'resources': [{'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}], 'date': 1432518282712}]}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')

    url = "https://andymartin.cc/test-pages/one-script-by-link.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world.js'}]}], 'id': 'b81cfef4f4c8515c985de28f290ca1b4577e7500bb166b26b2a3e6eecebe3363', 'url': 'https://andymartin.cc/test-pages/one-script-by-link.html'}]}
    check_search_data(url, correct)
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')

    url = "https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html', 'id': 'bcbd228cb9bbd1128c50e4f3bde5806820f056777574dc026e0b500023436228'}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')
     
    url = "https://andymartin.cc/test-pages/iframe-simple.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'hash': '24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html'}, {'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/iframe-simple.html', 'id': 'f258a9cfcf7a307ad8adefcd7d2ae1935ce97584375346db0951b762a3691b6c'}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')
    # require IFRAME content posting is turned on:
    check_script_content('24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b')  

    url = "https://andymartin.cc/test-pages/iframe-dropped.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'hash': '24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html'}, {'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}, {'hash':'2fbd3d57f0b0aa1e3bf0baf1f5e475f2e90b41053c8a0f0b11a0608e416a3adf', 'url': 'inline_script_2fbd3d57f0b0aa1e3b'}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/iframe-dropped.html', 'id': '0011c8873b915ea0f61df1de7b0deafea4d69f88421a649e3bb9ca68827beaed'}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')
    check_script_content('2fbd3d57f0b0aa1e3bf0baf1f5e475f2e90b41053c8a0f0b11a0608e416a3adf')
    # require IFRAME content posting is turned on:
    check_script_content('24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b')

    url = "https://andymartin.cc/test-pages/iframe-simple-nested.html"
    correct = {'objects': [{'pageviews': [{'resources': [{"url":"https://andymartin.cc/test-pages/iframe-simple.html","hash":"73a8712953772399e5567ad30082b395a05a0786bad6b901f46d42418ef69b7a"}, {'hash': '24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html'}, {'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/iframe-simple-nested.html', 'id': '0651e6fed8963e2a70d98789768fc7ea3b8098023ccdcc3b303caeb049a268e4'}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')
    # require IFRAME content posting is turned on:
    check_script_content('73a8712953772399e5567ad30082b395a05a0786bad6b901f46d42418ef69b7a')
    check_script_content('24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b')
 
    url = "https://andymartin.cc/test-pages/iframe-dropped-nested.html"
    correct = {'objects': [{'pageviews': [{'resources': [{"url":"https://andymartin.cc/test-pages/iframe-dropped.html","hash":"214678cac8b4b1c8e127feaeaa8d0b81e41ba4082aa78cd601bbb09e4ca1a6d8"}, {'hash': '24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b', 'url': 'https://andymartin.cc/test-pages/one-script-by-inline-and-one-by-link.html'}, {'url': 'https://andymartin.cc/test-pages/hello-world.js', 'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e'}, {'url': 'inline_script_b97dc449b77078dc8b', 'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab'}, {'hash':'2fbd3d57f0b0aa1e3bf0baf1f5e475f2e90b41053c8a0f0b11a0608e416a3adf', 'url': 'inline_script_2fbd3d57f0b0aa1e3b'}, {"url":"inline_script_5ee0b62e7babeeb8c5","hash":"5ee0b62e7babeeb8c58ee099f9caca099c94d3b0bd2bb5079021394102ed91b7"}], 'date': 1432509413332}], 'url': 'https://andymartin.cc/test-pages/iframe-dropped-nested.html', 'id': 'c2e7d4c89995ac582e86f4a19bd4b0f8bea81d8de70396d10df3a3bb2d2ee1a8'}]}
    check_search_data(url, correct)
    check_script_content('b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab')
    check_script_content('fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e')
    check_script_content('5ee0b62e7babeeb8c58ee099f9caca099c94d3b0bd2bb5079021394102ed91b7')
    check_script_content('2fbd3d57f0b0aa1e3bf0baf1f5e475f2e90b41053c8a0f0b11a0608e416a3adf')
    # require IFRAME content posting is turned on:
    check_script_content('24a3d764ffedc8a8dbe186da30dfbd2e3b27bebb9ea91e766fb37f097e38df0b')
    check_script_content('214678cac8b4b1c8e127feaeaa8d0b81e41ba4082aa78cd601bbb09e4ca1a6d8')

 
    # REDIRECT-REMOTE.HTML
    url = "https://andymartin.cc/test-pages/redirect-remote.html"
    correct = {'objects': [{'pageviews': [{'resources': [{"url":"https://andymartin.cc/test-pages/js/redirect.js","hash":"f7d41e0426b66e02e78c32f9d61d60c059b442d1cdaee67b74ec35d17283fe80"}]}], 'id': 'c41e236bb2dcb4bb70f53d14c552a5b0624b5fefeed530428ea5b27de94b45a3', 'url': 'https://andymartin.cc/test-pages/redirect-remote.html'}]}
    check_search_data(url, correct)
    url = "https://andymartin.cc/test-pages/end.html"
    correct = {'objects': [{'pageviews': [{'resources': []}, {'resources': []}], 'id': '7ba166d77694f20c8713278bd3d98a231b5a6db67f43515d8c35fd821c024d48', 'url': 'https://andymartin.cc/test-pages/end.html'}]}
    check_search_data(url, correct)

    # REDIRECT-INLINE.HTML
    url = "https://andymartin.cc/test-pages/redirect-inline.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'hash': '8155327a98a90fd75e8bf08eb6c02a316ca920dca2b06b9c6f7abbadbac31d31', 'url': 'inline_script_8155327a98a90fd75e'}]}], 'id': 'cb00b1e06896b0850c9bf84138ccd311f2afbcd80e3612f2174be9f4918910eb', 'url': 'https://andymartin.cc/test-pages/redirect-inline.html'}]}
    check_search_data(url, correct)
    url = "https://andymartin.cc/test-pages/end.html"
    correct = {'objects': [{'pageviews': [{'resources': []}, {'resources': []}], 'id': '7ba166d77694f20c8713278bd3d98a231b5a6db67f43515d8c35fd821c024d48', 'url': 'https://andymartin.cc/test-pages/end.html'}]}
    check_search_data(url, correct)
 
    # 10 SCRIPTS ON ONE PAGE
    url = "https://andymartin.cc/test-pages/10-scripts.html"
    correct = {'objects': [{'pageviews': [{'resources': [ {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-2.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-3.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-4.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-5.js'}]}], 'id': '4b7543d983ae9d7974eaa2237e357b82945624d85a98502d5d1ef80a2cb4b505', 'url': 'https://andymartin.cc/test-pages/10-scripts.html'}]}
    check_search_data(url, correct)

    # 100 SCRIPTS ON ONE PAGE
    url = "https://andymartin.cc/test-pages/100-scripts.html"
    correct = {'objects': [{'pageviews': [{'resources': [{'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'b97dc449b77078dc8b6af5996da434382ae78a551e2268d0e9b7c0dea5dce8ab', 'url': 'inline_script_b97dc449b77078dc8b'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-2.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-3.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-4.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-5.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-6.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-7.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-8.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-9.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-10.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-11.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-12.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-13.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-14.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-15.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-16.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-17.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-18.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-19.js'}, {'hash': 'fefe7a6e59e3a20f28adc30e89924ee99110edbf3351d0f9d65956159f635c0e', 'url': 'https://andymartin.cc/test-pages/hello-world-20.js'}]}], 'id': 'bf30874a3e146c7e66717cef66847117dc7e106c3abf8337d05474de8270c003', 'url': 'https://andymartin.cc/test-pages/100-scripts.html'}]}
    check_search_data(url, correct)
    
    # We're done!
    robobrowser.terminate()
    backend.terminate()


