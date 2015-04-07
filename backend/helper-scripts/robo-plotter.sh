#!/bin/bash
#

while :
do
    date 
    ./plot-total-observations-over-time.py /home/andy/projects/ScriptObservatory/backend/static/img/

    sleep 300  # 5 minutes
    ./plot-observations-per-hour.py /home/andy/projects/ScriptObservatory/backend/static/img/


    sleep 28800  # 8 hours

done

