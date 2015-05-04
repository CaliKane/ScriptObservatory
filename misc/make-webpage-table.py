#!/usr/bin/env python3
#

import hashlib
import sqlite3
import time


conn = sqlite3.connect('../backend/database.db')


URLS = []

cursor = conn.cursor()

print("clearing old webpage table")
cursor.execute("DELETE FROM webpage")

print("getting all pageviews")
cursor.execute("SELECT * FROM pageview")
pageviews = cursor.fetchall()

print("going through {0} pageview records".format(len(pageviews)))
for p in pageviews:
    URLS.append(p[1])

URLS = list(set(URLS))
print(len(URLS))

print("adding to webpage table")
for i,url in enumerate(URLS):
    if i % 500 == 0: print(i)
    
    h = hashlib.sha256(bytes(url, 'utf-8')).hexdigest()
    cursor.execute("INSERT INTO webpage(id, url) VALUES(?,?)", (h, url))

print("committing changes...")
conn.commit()
conn.close()

print("done!")

    
