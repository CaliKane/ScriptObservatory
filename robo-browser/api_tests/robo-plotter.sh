#!/bin/bash
#

while :
do
    date 

    ./plot-total-observations-over-time.py /home/andy/projects/ScriptObservatory/backend/static/img/
    ./plot-observations-per-hour.py /home/andy/projects/ScriptObservatory/backend/static/img/

    sleep 86400
done

