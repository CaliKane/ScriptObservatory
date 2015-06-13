#!/usr/bin/env python
#

import json
import requests
import sys

API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"

task = {'url': unicode(sys.argv[1]), 'priority': int(sys.argv[2])}

r = requests.post(API_BASE_URL, 
                  data=json.dumps(task), 
                  headers={"content-type": "application/json"}, 
                  verify=False)

print(r.status_code)


