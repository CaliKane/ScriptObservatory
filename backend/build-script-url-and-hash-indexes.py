#!/usr/bin/env python2
#

import sqlite3
import time


while True:
    conn = sqlite3.connect('database.db')

    print("clearing previous index tables...")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scripturlindex")
    cursor.execute("DELETE FROM scripthashindex")


    parent_url_index = {}

    print("building parent_url_index mapping...")
    cursor.execute("SELECT * FROM pageview")
    pageviews = cursor.fetchall()

    print("going through {0} pageview records".format(len(pageviews)))
    for p in pageviews:
        parent_url_index[p[0]] = p[1]


    url_index = {}
    hash_index = {}

    print("building url_index & hash_index...")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM script")
    scripts = cursor.fetchall()

    print("going through {0} script records".format(len(scripts)))
    for s in scripts:
        pageview_id = s[1]
        url = s[2]
        hash = s[3]
        if url not in url_index.keys():
            url_index[url] = ""
        if hash not in hash_index.keys():
            hash_index[hash] = ""

        parent_url = parent_url_index[pageview_id]
        
        # duplicates are not allowed downstream by angular
        if parent_url not in url_index[url]:
            url_index[url] += "{0},".format(parent_url)

        if parent_url not in hash_index[hash]:
            hash_index[hash] += "{0},".format(parent_url)

    print("adding script_urls & page_urls to url_index")
    for url in url_index.keys():
        cursor.execute("INSERT INTO scripturlindex(script_url, page_urls) VALUES(?,?)", (url, url_index[url][:-2]))

    print("adding script_hashes & page_urls to hash_index")
    for hash in hash_index.keys():
        cursor.execute("INSERT INTO scripthashindex(script_hash, page_urls) VALUES(?,?)", (hash, hash_index[hash][:-2]))

    print("committing changes...")
    conn.commit()
    conn.close()

    print("done!")
    
    
    time.sleep(6*60*60) # once every 6 hours
