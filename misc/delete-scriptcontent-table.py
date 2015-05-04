#!/usr/bin/env python3
#

import hashlib
import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')


URLS = []

cursor = conn.cursor()

print("getting all scriptcontent")
cursor.execute("DELETE FROM scriptcontent limit 10")

conn.commit()
conn.close()

print("done!")

    
