#!/usr/bin/env python3
#
# robo-scheduler.py 
#

import json
import requests
import sys
import time

import schedule


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"


def add_list_file(list_filename, priority):
    for line in open(list_filename, 'r'):
        url = line.strip()

        task = {'url': url, 'priority': priority}

        r = requests.post(API_BASE_URL, 
                          data=json.dumps(task), 
                          headers={"content-type": "application/json"}, 
                          verify=False)

        print(r.status_code)
        time.sleep(0.1)

#
# PRIORITIES:
#  1 --> manually added sites
#  2 --> daily sites
#  3 --> bi-weekly sites
#  4 --> weekly sites
#  5 --> monthly sites
#

def DAILY():
    print("running DAILY list!")
    pass
    print("done DAILY list!")

def BIWEEKLY():
    print("running BIWEEKLY list!")
    add_list_file("./website-lists/random.txt", 3)
    add_list_file("./website-lists/infosec-sites.txt", 3)
    add_list_file("./website-lists/fortune500.txt", 3)
    print("done BIWEEKLY list!")
 
def WEEKLY():
    print("running WEEKLY list!")
    add_list_file("./website-lists/universities.txt", 4)
    add_list_file("./website-lists/alexa-top-1k.txt", 4)
    print("done WEEKLY list!")

monthly_ctr = 0
def MONTHLY():
    global monthly_ctr
    monthly_ctr += 1
    print("monthly_ctr == {0}".format(monthly_ctr))

    if monthly_ctr >= 4:
        print("running MONTHLY list!")
        add_list_file("./website-lists/alexa-top-10k.txt", 5)
        monthly_ctr = 0
        print("done MONTHLY list!")


schedule.every().day.do(DAILY)

schedule.every().monday.do(BIWEEKLY)
schedule.every().thursday.do(BIWEEKLY)

schedule.every().sunday.do(WEEKLY)

schedule.every().week.do(MONTHLY)  # logic to force it to run monthly in MONTHLY() for now


while True:
    schedule.run_pending()
    time.sleep(5)

