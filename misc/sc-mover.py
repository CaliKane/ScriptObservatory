#!/usr/bin/env python3
#

import os
import sys


for filename in os.listdir("./")[::-1]:
    if not filename.endswith(".txt.gz"): continue
    new_dir = filename[0:4]

    #print("mv {0} {1}/".format(filename, new_dir))
    os.system("mv {0} {1}/".format(filename, new_dir))

