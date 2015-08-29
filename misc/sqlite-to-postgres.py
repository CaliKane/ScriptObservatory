#!/usr/bin/env python3
#
# CREATE INDEX webpage_index ON pageview (url);
# CREATE INDEX pageview_index ON resource (pageview_id);
# CREATE INDEX resource_url_index ON resource (url);
# CREATE INDEX resource_hash_index ON resource (hash);


import datetime
import hashlib
import psycopg2
import sqlite3
import sys


conn_old = sqlite3.connect('./database-arch-3.db')
conn_new = psycopg2.connect("host='localhost' user='postgres' password='pg2'")

cursor_old = conn_old.cursor()
cursor_new = conn_new.cursor()

## WEBPAGE TABLE
def do_webpage_table():
    cursor_old.execute("SELECT * FROM webpage ")
    webpages = cursor_old.fetchall()

    print("going through {0} webpage records".format(len(webpages)))
    ten_perc = len(webpages)//10
    for i, w in enumerate(webpages):
        if i % ten_perc == 0: print(i)
        h, url = w
        
        if not url or not h: 
            print("None object encountered!")
            continue

        if len(url) > 2048: 
            continue
        
        final = (h, url)
        #print("{0}".format(final))
        cursor_new.execute("INSERT INTO webpage(id, url) VALUES(%s, %s)", final)


## PAGEVIEW TABLE
def do_pageview_table():
    cursor_old.execute("SELECT * FROM pageview")
    pageviews = cursor_old.fetchall()

    print("going through {0} pageview records".format(len(pageviews)))
    ten_perc = len(pageviews)//10
    for i,pv in enumerate(pageviews):
        if i % ten_perc == 0: print(i)
        id, url, date = pv

        if not id or not url or not date: 
            print("None object encountered!")
            continue
        
        if len(url) > 2048: 
            continue
        
        # process date
        date = datetime.datetime.fromtimestamp(date/1000)

        #h = str(hashlib.sha256(url.encode('utf-8')).hexdigest())

        final = (id, url, date)
        #print("{0}".format(final))
        cursor_new.execute("INSERT INTO pageview(id, url, date) VALUES(%s, %s, %s)", final)


## SCRIPT/RESOURCE TABLE
def do_resource_table():
    start = end = 0
    while True:
        start = end
        end = start + 1000000
        cursor_old.execute("SELECT * FROM script WHERE id >= {0} and id < {1}".format(start, end))
        scripts = cursor_old.fetchall()

        if len(scripts) == 0:
            print("done!")
            break

        print("going through {0} script records".format(len(scripts)))
        ten_perc = len(scripts)//5
        for i,s in enumerate(scripts):
            if i % ten_perc == 0: print(i)
            id, pageview_id, url, hash = s
            type = 'unk' 

            if not id or not pageview_id or not url or not hash: 
                print("None object encountered!")
                continue
            
            if len(url) > 2048: 
                continue
            
            final = (id, pageview_id, url, hash, type)
            #print("{}".format(final))
    
            try:
                cursor_new.execute("INSERT INTO resource(id, pageview_id, url, hash, type) VALUES(%s, %s, %s, %s, %s)", final)
            except psycopg2.IntegrityError:
                print("Caught error: {}".format(sys.exc_info()))
            except psycopg2.InternalError:
                print("Caught error: {}".format(sys.exc_info()))

        conn_new.commit()
        print("committed")

#do_webpage_table()
#conn_new.commit()

#do_pageview_table()
#conn_new.commit()

do_resource_table()

conn_new.close()

print("done!")


