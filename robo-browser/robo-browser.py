#!/usr/bin/env python2
#

from __future__ import print_function

import json
import os
import requests
import sys
import time

import selenium

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"
N_SECS_TO_WAIT_AFTER_ONLOAD = 20
N_SECS_REQ_TIMEOUT = 100
N_SECS_BETWEEN_PAGES = 1


while True:
    try:
        # get next task from robotask API
        response = requests.get(API_BASE_URL, 
                                params=dict(q=json.dumps(dict(field='priority', direction='asc'))),
                                headers={'Content-Type': 'application/json'},
                                verify=False)

        assert response.status_code == 200
        task = response.json()

        if len(task["objects"]) == 0:
            print("no jobs currently in the queue")
            time.sleep(10)
            continue

        priority = task["objects"][0]["priority"]
        url = task["objects"][0]["url"]
        id = task["objects"][0]["id"]
        print("got task:", id, priority, url)

        
        # go fetch the page in our browser
        web_addr = str(url)
        
        options = Options()
        options.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))

        driver = webdriver.Chrome(chrome_options=options)
        driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)
        driver.get(web_addr)

        time.sleep(N_SECS_TO_WAIT_AFTER_ONLOAD)


        # remove our job from the queue
        response = requests.delete("{0}/{1}".format(API_BASE_URL, id), verify=False)
        assert response.status_code == 204

    except selenium.common.exceptions.TimeoutException:
        print("the page load timed out for {0} - continuing...".format(web_addr))

driver.quit()

