#!/usr/bin/env python3
#

import sys
import time

from backend import app
import backend.tasks


hours_ago = int(sys.argv[1])

for substr in app.config['MONITORED_SUBSTRS']:
    print("scanning {}".format(substr))
    backend.tasks.schedule_suspicious_scan(substr, start_n_hours_ago=hours_ago)
    time.sleep(1)

