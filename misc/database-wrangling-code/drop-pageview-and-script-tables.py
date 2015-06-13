#!/usr/bin/env python2
#

import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')

print("clearing tables...")
cursor = conn.cursor()
cursor.execute("DELETE FROM pageview")
cursor.execute("DELETE FROM script")


print("committing changes...")
conn.commit()
conn.close()

print("done!")

    
