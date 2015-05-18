#!/usr/bin/env python
#
# first test for nose
#

import requests


def test_test():
    print("testing!")

def test_get_robotasks():
    r = requests.get("https://scriptobservatory.org/api/robotask",
                     headers={'content-type': 'application/json'})

    print(r.status_code, r.data)
    assert r.status_code == 200


