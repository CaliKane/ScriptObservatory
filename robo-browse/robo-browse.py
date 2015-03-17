#!/usr/bin/env python2
#

from __future__ import print_function

import os
import random
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options


N_SECS_BETWEEN_PAGES = 10
N_SECS_REQ_TIMEOUT = 60
MAX_CLICKS_PER_SITE = 10

EXTENSION_PATH = "/home/andy/projects/ScriptObservatory/chrome-extension/"  # TODO
WEB_ADDR_LIST = "/home/andy/projects/ScriptObservatory/robo-browse/site-list.txt"  # TODO


def get_webpage(driver, web_address, return_n_links=0):
    driver.get(web_address)

    links = []

    for element in driver.find_elements_by_tag_name('a'):
        try:
            links.append(element.get_attribute("href"))            
        except:
            print("found an 'a' element without a href attribute")
    
    random.shuffle(links)

    return links[:return_n_links]     


# Set up Selenium
chrome_options = Options()
chrome_options.add_argument("--load-extension={0}".format(EXTENSION_PATH))

driver = webdriver.Chrome(chrome_options=chrome_options)
driver.set_page_load_timeout(N_SECS_REQ_TIMEOUT)

url_list = []

# Go through the list from WEB_ADDR_LIST
for web_address in open(WEB_ADDR_LIST, 'r'):
    web_address = web_address.strip()
    
    new_urls = get_webpage(driver, web_address, return_n_links=MAX_CLICKS_PER_SITE)
    url_list += new_urls

    time.sleep(N_SECS_BETWEEN_PAGES)

#
# TODO implement recursive link traversal...allow "depth" parameter to be set
#                                        ...look at robots.txt
#
# Go through the links found on pages from WEB_ADDR_LIST
#for web_address in url_list:
#    web_address = web_address.strip()
#
#    get_webpage(driver, web_address)
#    time.sleep(N_SECS_BETWEEN_PAGES)
#

# Close our browser
driver.quit()


