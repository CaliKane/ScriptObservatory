#!/usr/bin/env python
#

import json
import requests
import sys

API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"

task = {'url': u"https://www.andymartin.cc", 'priority': int(sys.argv[1])}

r = requests.post(API_BASE_URL, 
                  data=json.dumps(task), 
                  headers={"content-type": "application/json"}, 
                  verify=False)

print(r.status_code)


