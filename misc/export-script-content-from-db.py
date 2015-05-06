#!/usr/bin/env python2
#

import json  # import simplejson as json, if on Python 2.5
import os
import requests  # python-requests is installable from PyPI...
import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM scriptcontent")

SCRIPT_CONTENT_FOLDER = "/home/andy/projects/ScriptObservatory/backend/static/script-content/"


while True:
    scripts = cursor.fetchmany(1000)
    print(len(scripts))
    if len(scripts) == 0: break

    for p in scripts:
        h = p[0]
        content = p[1]
        
        sc = {'sha256': h, 'content': content}

        print("posting {0}".format(h))

        r = requests.post('https://scriptobservatory.org/script-content', 
                          data=json.dumps(sc),
                          headers={'content-type': 'application/json'},
                          verify=False)

        assert r.status_code == 200
        time.sleep(0.3)

conn.close()

