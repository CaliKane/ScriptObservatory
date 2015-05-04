#!/usr/bin/env python3
#

import hashlib
import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')


URLS = []

cursor = conn.cursor()

print("getting all scriptcontent")
cursor.execute("SELECT * FROM scriptcontent")
scriptcontent = cursor.fetchall()

print("going through {0} scriptcontent records".format(len(pageviews)))

exit()

print("adding to webpage table")
for i,url in enumerate(URLS):
    if i % 500 == 0: print(i)
    
    h = hashlib.sha256(bytes(url, 'utf-8')).hexdigest()
    cursor.execute("INSERT INTO webpage(id, url) VALUES(?,?)", (h, url))

print("committing changes...")
conn.commit()
conn.close()

print("done!")

    
