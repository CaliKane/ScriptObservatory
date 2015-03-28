#!/usr/bin/env python2
#

from __future__ import print_function

import os
import sys
import time

import selenium

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


N_SECS_TO_WAIT_AFTER_ONLOAD = 20
N_SECS_REQ_TIMEOUT = 100
N_SECS_BETWEEN_PAGES = 1
URL_LIST = sys.argv[1]

for web_addr in open(URL_LIST, 'r'):
    try:
        web_addr = web_addr.strip()
        
        options = Options()
        options.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))

        driver = webdriver.Chrome(chrome_options=options)
        driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)
        driver.get(web_addr)

        time.sleep(N_SECS_TO_WAIT_AFTER_ONLOAD)

    except selenium.common.exceptions.TimeoutException:
        print("the page load timed out for {0} - continuing...".format(web_addr))

    driver.quit()

