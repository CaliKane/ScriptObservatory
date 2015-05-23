#!/usr/bin/env python3
#
# first test for nose
#

import os
import requests
import subprocess
import time


def test_test():
    print("testing!")


def test_get_robotasks():
    print("launching backend.py")
    filepath = os.path.dirname(os.path.realpath(__file__))
    s = subprocess.Popen(["python3.4", "{0}".format(os.path.join(filepath, "../backend/backend.py"))])
    
    time.sleep(1)

    r = requests.get("http://127.0.0.1:8080/api/robotask",
                     headers={'content-type': 'application/json'})

    print(r.status_code, r.text)
    assert r.status_code == 200

    s.terminate()

    """
    newperson = {'name': u'Lincoln', 'age': 23}
    r = requests.post('/api/person', data=json.dumps(newperson),
                      headers={'content-type': 'application/json'})
    r.status_code, r.headers['content-type'], r.data
    """
