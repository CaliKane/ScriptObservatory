#!/usr/bin/env python2
#

import json
import requests

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pylab import *

axes = figure().add_subplot(111)

API_BASE_URL = "https://www.scriptobservatory.org/api/pageview"
N_X_LABELS = 5
N_DATA_POINTS = 250
OUTPUT_BASEDIR = sys.argv[1]  #/static/img/ directory


# get the list of all pageviews from the pageview API:
response = requests.get(API_BASE_URL, 
                        headers={'Content-Type': 'application/json'},
                        verify=False)

if response.status_code != 200:
    print("GET returned non-200 response code! exiting...")
    exit()

pageviews = response.json()["objects"]
print "got", len(pageviews), "objects"
 

pv_times = []

 
t_first = int(pageviews[0]["date"])
t_last = int(pageviews[-1]["date"])
t_elapsed = t_last - t_first
time_vals = range(t_first, t_last, t_elapsed/N_DATA_POINTS)

y = []
labels = []

time_vals_ind = 0
obs_so_far = 0
for n, pv in enumerate(pageviews):
    t = int(pv["date"])
    obs_so_far += len(pv["scripts"])

    if t > time_vals[time_vals_ind]:
        y.append(obs_so_far)
        labels.append(t)
        time_vals_ind += 1

plt.plot(range(len(y)), y, 'r-')
plt.ylabel("Total observations")

xmin, xmax, ymin, ymax = plt.axis()
plt.axis([xmin, xmax, 0, ymax+10])
n_labels = len(axes.get_xticklabels())

time_labels = range(t_first, t_last, t_elapsed/n_labels)

for i in range(len(time_labels)):
    time_labels[i] = datetime.datetime.fromtimestamp(time_labels[i]/1000).strftime('%m/%d')
time_labels[0] = ""

axes.set_xticklabels(time_labels)

plt.savefig(OUTPUT_BASEDIR + "/entries-over-time.png")

