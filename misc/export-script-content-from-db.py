#!/usr/bin/env python2
#

import os
import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')
cursor = conn.cursor()
cursor.execute("SELECT * FROM scriptcontent")
scripts = cursor.fetchall()

SCRIPT_CONTENT_FOLDER = "/home/andy/projects/ScriptObservatory/backend/static/script-content/"

i = 0
for p in scripts:
    i += 1
    h = p[0]
    print(h)
    content = p[1]
    
    with open(os.path.join(SCRIPT_CONTENT_FOLDER, "{0}.txt".format(h)), 'w') as f:
        f.write(content.encode('utf8'))

    if i > 1000: 
        break

conn.close()


