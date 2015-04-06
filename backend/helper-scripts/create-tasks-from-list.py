#!/usr/bin/env python
#

import os
import sys
import time


list_filename = sys.argv[1]
priority = int(sys.argv[2])

for line in open(list_filename, 'r'):
    line = line.strip()
    os.system("python create-task.py {0} {1}".format(line, priority))
    time.sleep(0.1)

