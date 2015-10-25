#!/usr/bin/env python3
#

import datetime
import os

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from pylab import *
axes = figure().add_subplot(111)

sys.path.append(os.path.join(os.path.dirname(__file__), '../..'))
from backend.models import Webpage, Pageview, Resource


OUTPUT_BASEDIR = sys.argv[1]  #/static/img/ directory

y = []
x = []

end_t = datetime.datetime(2015, 4, 1)
while True:
    start_t = end_t
    end_t += datetime.timedelta(days=2)
    
    if end_t > datetime.datetime.now(): 
        break

    views = Pageview.query.filter(Pageview.date < end_t).filter(Pageview.date >= start_t).all()
    
    y.append(len(views) / (24 * 1000))
    x.append(start_t)

plt.plot(x, y, 'r-')
plt.title("New Pageview Observations Added Per Hour")
plt.ylabel("Thousands of pageviews")

xmin, xmax, ymin, ymax = plt.axis()
plt.axis([xmin, xmax, 0, ymax])

dateFmt = matplotlib.dates.DateFormatter('%m/%d')
axes.xaxis.set_major_formatter(dateFmt)
axes.xaxis.get_major_ticks()[0].label1.set_visible(False)

os.system("rm {0}/new-entries-per-hour.png".format(OUTPUT_BASEDIR))
plt.savefig(OUTPUT_BASEDIR + "/new-entries-per-hour.png")
