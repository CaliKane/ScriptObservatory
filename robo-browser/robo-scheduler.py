#!/usr/bin/env python3
#

import json
import logging
import requests
import sys
import time


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"


#
# SUGGESTED PRIORITIES:
#  1 --> manually added sites
#  2 --> daily sites
#  3 --> bi-weekly sites
#  4 --> weekly sites
#  5 --> monthly sites
#

def add_list_file(list_filename, priority):
    logging.warn("adding {0} at priority {1}".format(list_filename, priority))
    for line in open(list_filename, 'r'):
        url = line.strip()

        task = {'url': url, 'priority': priority}

        r = requests.post(API_BASE_URL, 
                          data=json.dumps(task), 
                          headers={"content-type": "application/json"}, 
                          verify=False)

        if r.status_code == 201:
            logging.warn("success!")
        else:
            logging.error(r.status_code)
        
        time.sleep(0.75)


if __name__ == "__main__":
    logging.basicConfig(filename="/home/andy/projects/ScriptObservatory/robo-browser/scheduler-log.txt", level=logging.WARN)
    logging.warn("current time: {0}".format(time.strftime("%a, %d %b %Y %H:%M:%S +0000", time.gmtime())))
    logging.warn("being called with: {0}".format(sys.argv))

    priority = int(sys.argv[1])
    
    for arg in sys.argv[2:]:
        # we make sure the file is really a domain list by checking for the .list ending
        if not arg.endswith(".list"):
            continue
        
        add_list_file(arg, priority)
    
    logging.warn("done!")

