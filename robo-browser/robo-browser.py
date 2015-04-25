#!/usr/bin/env python2
#
# robo-browser.py gets the next website from the robotask API and browses to it using
# a selenium webdriver with the scriptobservatory chrome extension installed. It repeats 
# this forever, using a "fake" Xvfb display to run headlessly.
#

import json
import logging
import multiprocessing
import os
import requests
import subprocess
import sys
import time

import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from xvfbwrapper import Xvfb


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"

N_SECS_TO_WAIT_AFTER_ONLOAD = 25
N_SECS_TO_WAIT_AFTER_ERR = 20
N_SECS_TO_WAIT_FOR_CHROME_EXT = 2
N_SECS_REQ_TIMEOUT = 75
N_SECS_HARD_REQ_TIMEOUT = 90

OPTIONS = Options()
OPTIONS.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))
OPTIONS.add_argument("--disable-application-cache")


class RoboBrowseException(Exception):
    # we can just inherit from Exception
    pass


def get_next_robotask():
    """ returns the (url, priority, task_id) of next task, raises RoboBrowseException on error """
    response = requests.get(API_BASE_URL, 
                            params=dict(q=json.dumps(dict(order_by=[dict(field='priority', direction='asc')]))),
                            headers={'Content-Type': 'application/json'},
                            verify=False)

    if response.status_code != 200:
        raise RoboBrowseException("GET returned non-200 response code! trying again...")

    task = response.json()

    if len(task["objects"]) == 0:
        raise RoboBrowseException("no jobs currently in the queue")

    current_task = task["objects"][0]
    logging.warn("got task for url: {0}".format(current_task["url"]))
    return (current_task["url"], current_task["priority"], current_task["id"])


def delete_robotask(task_id):
    """ returns if *task_id* is successfully deleted, raises RoboBrowseException on error """
    response = requests.delete("{0}/{1}".format(API_BASE_URL, task_id), verify=False)
    
    if response.status_code != 204:
        # a non-204 status is returned if someone else has already deleted the task, so 
        # this lets us be sure we won't run a given task more than once.
        raise RoboBrowseException("GET returned non-200 response code! ...trying again...")


def fetch_webpage(url):
    """ creates a chrome webdriver and navigates to *url* """
    try:
        driver = webdriver.Chrome(chrome_options=OPTIONS) 
        driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)
        time.sleep(N_SECS_TO_WAIT_FOR_CHROME_EXT)
        driver.get(url)
        time.sleep(N_SECS_TO_WAIT_AFTER_ONLOAD)
        logging.warn("done!")
    
    except selenium.common.exceptions.WebDriverException:
        logging.error("tab crashed!")
 



if __name__ == "__main__":
    logging.basicConfig(filename="log-robobrowse-{0}.txt".format(time.time()), level=logging.WARN)
    
    vdisplay = Xvfb()
    vdisplay.start()
     
    while True:
        try:
            url, priority, task_id = get_next_robotask()
            delete_robotask(task_id)
            p = multiprocessing.Process(target=fetch_webpage, args=(url,))
            p.start()
            p.join(N_SECS_HARD_REQ_TIMEOUT)
            if p.is_alive():
                p.terminate()
                logging.error("hit HARD_REQ_TIMEOUT. terminating process....")
                
        except RoboBrowseException, e:
            logging.error("ERROR: {0} -- continuing on...".format(e))
            time.sleep(N_SECS_TO_WAIT_AFTER_ERR)

    vdisplay.stop()

