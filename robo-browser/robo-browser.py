#!/usr/bin/env python3
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
import signal
import subprocess
import sys
import time

import selenium
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

from xvfbwrapper import Xvfb


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"

N_SECS_TO_WAIT_AFTER_ONLOAD = 16
N_SECS_TO_WAIT_AFTER_ERR = 20
N_SECS_TO_WAIT_FOR_CHROME_EXT = 2
N_SECS_REQ_TIMEOUT = 70
N_SECS_HARD_REQ_TIMEOUT = 90

OPTIONS = Options()
OPTIONS.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))
OPTIONS.add_argument("--disable-application-cache")


class SigtermException(Exception):
    # we can just inherit from the plain Exception class
    pass


class RoboBrowseException(Exception):
    # we can just inherit from the plain Exception class
    pass


def sigterm_handler(_signo, _stack_frame):
    logging.error("caught SIGTERM! raising SigtermException to recreate the Xvfb display")
    raise SigtermException


def get_next_robotask():
    """ gets the (url, priority, task_id) of next task or raise a RoboBrowseException on error """
    response = requests.get(API_BASE_URL, 
                            params=dict(q=json.dumps(dict(order_by=[dict(field='priority', direction='asc')]))),
                            headers={'Content-Type': 'application/json'},
                            verify=False)

    if response.status_code != 200:
        raise RoboBrowseException("GET returned non-200 response code!")

    task = response.json()

    if len(task["objects"]) == 0:
        raise RoboBrowseException("no jobs currently in the queue")

    current_task = task["objects"][0]
    return (current_task["url"], current_task["priority"], current_task["id"])


def delete_robotask(task_id):
    """ deletes the task with id *task_id* from the robotask API or raises a RoboBrowseException on error """
    response = requests.delete("{0}/{1}".format(API_BASE_URL, task_id), verify=False)
    
    if response.status_code != 204:
        # a non-204 status is most often returned if someone else has already deleted the task. We raise a 
        # RoboBrowseException so we go and get the next task instead of running this one 
        raise RoboBrowseException("DELETE returned non-204! someone else likely already got this task.")


def fetch_webpage(url):
    """ fetch_webpage creates a chrome webdriver and navigates to *url* """
    try:
        driver = webdriver.Chrome(chrome_options=OPTIONS) 
        driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)
        time.sleep(N_SECS_TO_WAIT_FOR_CHROME_EXT)
        driver.get(url)
        time.sleep(N_SECS_TO_WAIT_AFTER_ONLOAD)
        logging.warn("done!")
    
    except selenium.common.exceptions.WebDriverException as e:
        logging.error("tab crashed! err: {0}".format(e))

    except selenium.common.exceptions.TimeoutException as e:
        logging.error("the page load timed out! err: {0}".format(e))

    finally:
        driver.quit()


if __name__ == "__main__":
    logging.basicConfig(filename="log-robobrowse-{0}.txt".format(time.time()), level=logging.WARN)
    signal.signal(signal.SIGTERM, sigterm_handler)

    vdisplay = Xvfb()
    vdisplay.start()
     
    while True:
        try:
            logging.warn("number of chrome / python processes: {0}".format(subprocess.check_output("ps aux | grep \"hrome\|python\" | wc -l", shell=True)))

            url, priority, task_id = get_next_robotask()
            logging.warn("got task for url: {0}".format(url))
            delete_robotask(task_id)
            p = multiprocessing.Process(target=fetch_webpage, args=(url,))
            p.start()
            MY_PID = p.pid
            p.join(N_SECS_HARD_REQ_TIMEOUT)
            if p.is_alive():
                # if p is still alive after N_SECS_HARD_REQ_TIMEOUT, something's gone very wrong with the Selenium
                # webdriver. In the past, the driver.quit() call has often been the place where it gets stuck.
                # There really isn't anything we can do to recover, so we destroy all processes with the given
                # PGID. To avoid destroying ourselves, we catch SIGTERM in our main thread and try to continue after
                # recreating the Xvfb display.
                logging.error("running: kill -TERM -{0}".format(MY_PID))
                out = subprocess.check_output("kill -TERM -{0}".format(MY_PID), shell=True)
                logging.error("result: {0}".format(out))

        except RoboBrowseException as e:
            logging.error("ERROR: {0} -- continuing on...".format(e))
            time.sleep(N_SECS_TO_WAIT_AFTER_ERR)

        except subprocess.CalledProcessError as e:
            logging.error("ERROR: CalledProcessError {0} -- continuing on...".format(e))
            time.sleep(N_SECS_TO_WAIT_AFTER_ERR)
 
        except SigtermException as e:
            logging.error("ERROR: {0} -- continuing on...".format(e))
            
            # per notes above we need to recreate the Xvfb display because it will have been destroyed by our
            # call kill when trying to cleanly destroy a broken webdriver.
            logging.error("closing vdisplay")
            vdisplay.stop()
            logging.error("creating new vdisplay")
            vdisplay = Xvfb()
            vdisplay.start()
            time.sleep(N_SECS_TO_WAIT_AFTER_ERR)
            
    vdisplay.stop()

