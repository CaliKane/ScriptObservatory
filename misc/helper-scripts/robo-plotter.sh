#!/bin/bash
#

while :
do
    date 
    ./plot-total-observations-over-time.py /home/andy/projects/ScriptObservatory/backend/static/img/
    sleep 5  # 5 seconds
    ./plot-observations-per-hour.py /home/andy/projects/ScriptObservatory/backend/static/img/
    echo "done!"
    sleep 3600  # 1 hour

done

