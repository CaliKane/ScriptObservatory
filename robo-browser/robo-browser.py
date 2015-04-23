#!/usr/bin/env python2
#
# robo-browser.py gets the next website from the robotask API and browses to it using
# a selenium webdriver with the scriptobservatory chrome extension installed. It repeats 
# this forever, using a "fake" Xvfb display to run headlessly.
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
from xvfbwrapper import Xvfb


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"
N_SECS_TO_WAIT_AFTER_ONLOAD = 30
N_SECS_REQ_TIMEOUT = 90


vdisplay = Xvfb()
vdisplay.start()

options = Options()
options.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))
options.add_argument("--disable-application-cache")

while True:
    try:
        # get the next task from the robotask API:
        response = requests.get(API_BASE_URL, 
                                params=dict(q=json.dumps(dict(order_by=[dict(field='priority', direction='asc')]))),
                                headers={'Content-Type': 'application/json'},
                                verify=False)

        if response.status_code != 200:
            print("GET returned non-200 response code! ...trying again...")
            continue

        task = response.json()

        if len(task["objects"]) == 0:
            print("no jobs currently in the queue")
            time.sleep(20)
            continue

        priority = task["objects"][0]["priority"]
        url = task["objects"][0]["url"]
        task_id = task["objects"][0]["id"]
        print("got task for url:", url)

        # remove the job from the queue
        response = requests.delete("{0}/{1}".format(API_BASE_URL, task_id), verify=False)
        if response.status_code != 204:
            print("GET returned non-200 response code! ...trying again...")
            continue

        # go fetch the page in the selenium webdriver
        driver = webdriver.Chrome(chrome_options=options)
        driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)
        
        time.sleep(2)
        driver.get(url)
        print("done!")
        time.sleep(N_SECS_TO_WAIT_AFTER_ONLOAD)

    except selenium.common.exceptions.TimeoutException:
        print("the page load timed out for {0} - continuing on...".format(url))
        time.sleep(30)    

    except selenium.common.exceptions.WebDriverException:
        print("tab crashed!")
        time.sleep(30)
    
    try:
        driver.quit()
    except urllib2.URLError:
        print("urllib2.URLError thrown while calling driver.quit(), trying to continue...")
        time.sleep(30)


vdisplay.stop()

