#!/usr/bin/env python2
#

import json
import requests


API_BASE_URL = "https://www.scriptobservatory.org/api/robotask"


# get the next task from the robotask API:
response = requests.get(API_BASE_URL, 
                        params=dict(q=json.dumps(dict(order_by=[dict(field='priority', direction='asc')]))),
                        headers={'Content-Type': 'application/json'},
                        verify=False)

if response.status_code != 200:
    print("GET returned non-200 response code! ...trying again...")
    exit()

print response.json()
    
