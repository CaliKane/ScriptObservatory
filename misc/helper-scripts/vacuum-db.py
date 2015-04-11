#!/usr/bin/env python2
#

import sqlite3

conn=sqlite3.connect("../../backend/database.db")
conn.execute("VACUUM")
conn.commit()
conn.close()
