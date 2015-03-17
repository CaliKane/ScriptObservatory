#!/usr/bin/env python2
#

from __future__ import print_function

import os
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


N_SECS_BETWEEN_PAGES = 3
N_SECS_REQ_TIMEOUT = 60

if len(sys.argv) < 2:
    print("Run with ./robo-browse.py URL_LIST_FILE")
    exit()

WEB_ADDR_LIST = sys.argv[1]


options = Options()
options.add_argument("--load-extension={0}".format(os.environ['PATH_TO_EXTENSION']))

driver = webdriver.Chrome(chrome_options=options)
driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)

for web_addr in open(WEB_ADDR_LIST, 'r'):
    try:
        web_addr = web_addr.strip()
        driver.get(web_addr)
        time.sleep(N_SECS_BETWEEN_PAGES)
    except:
        print("the page load timed out for {0} - continuing...".format(web_addr))

driver.quit()


