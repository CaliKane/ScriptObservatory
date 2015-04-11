#!/usr/bin/env python2
#

import json
import requests
import sqlite3

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pylab import *

axes = figure().add_subplot(111)

N_X_LABELS = 5
N_DATA_POINTS = 250
OUTPUT_BASEDIR = sys.argv[1]  #/static/img/ directory



conn = sqlite3.connect('../../backend/database.db')

c = conn.cursor()

pageviews = list(c.execute("SELECT * FROM pageview"))
# format: id, url, time

pv_times = []

t_first = int(pageviews[0][2])
t_last = int(pageviews[-1][2])
t_elapsed = t_last - t_first
time_vals = range(t_first, t_last, t_elapsed/N_DATA_POINTS)
hours_per_tv = float(t_elapsed/N_DATA_POINTS) / (1000*60*60)

y = []
labels = []
URL_LIST = []

time_vals_ind = 0
obs_so_far = 0
for n, pv in enumerate(pageviews):
    url = pv[1]
    t = int(pv[2])
    
    if url not in URL_LIST:
        obs_so_far += 1  # len(pv["scripts"])
        URL_LIST.append(url)

    if t > time_vals[time_vals_ind]:
        #print obs_so_far / hours_per_tv
        y.append(obs_so_far/1000.0)
        labels.append(t)
        time_vals_ind += 1

plt.plot(range(len(y)), y, 'r-')
plt.title("Unique Webpages in Database")
plt.ylabel("1,000s of webpages")
xmin, xmax, ymin, ymax = plt.axis()
plt.axis([xmin, xmax, 0, ymax+10])
n_labels = len(axes.get_xticklabels())

time_labels = range(t_first, t_last, t_elapsed/n_labels)

for i in range(len(time_labels)):
    time_labels[i] = datetime.datetime.fromtimestamp(time_labels[i]/1000).strftime('%m/%d')
time_labels[0] = ""

axes.set_xticklabels(time_labels)

plt.savefig(OUTPUT_BASEDIR + "/unique-webpages-over-time.png")

