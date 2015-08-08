#!/usr/bin/env python3
#

import sqlite3
import sys
import time
import yara

conn = sqlite3.connect('./database.db')

cursor = conn.cursor()
sources = {}

email = "andy@andymartin.cc"
namespace = sys.argv[1]
with open(sys.argv[2], 'r') as source_file:
    source = source_file.read()

print("Got:\n{0}".format(source))

sources[namespace] = source
rules = yara.compile(sources=sources)
print("compiled successfully...")
cursor.execute("INSERT INTO yara_ruleset(email, namespace, source) VALUES(?,?,?)", (email, namespace, source))

conn.commit()
conn.close()
