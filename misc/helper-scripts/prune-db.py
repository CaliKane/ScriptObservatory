#!/usr/bin/env python2
#

import sqlite3


conn = sqlite3.connect('../../backend/database.db')

c = conn.cursor()

c.execute("DELETE FROM pageview WHERE Date < 1428375689187")
conn.commit()
c.close()
