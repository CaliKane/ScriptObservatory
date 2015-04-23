#!/usr/bin/env python3
#

import json
import requests
import sys
import time

import schedule


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"


def add_list_file(list_filename, priority):
    for line in open(list_filename, 'r'):
        line = line.strip()



task = {'url': unicode(sys.argv[1]), 'priority': int(sys.argv[2])}

r = requests.post(API_BASE_URL, 
                  data=json.dumps(task), 
                                    headers={"content-type": "application/json"}, 
                                                      verify=False)

                                                      print(r.status_code)


os.system("python2 create-task.py {0} {1}".format(line, priority))
        time.sleep(0.1)

