#!/bin/bash
#

while :
do
    date 
    ./plot-total-observations-over-time.py /home/andy/projects/ScriptObservatory/backend/static/img/
    ./plot-observations-per-hour.py /home/andy/projects/ScriptObservatory/backend/static/img/
    ./plot-unique-webpages-over-time.py /home/andy/projects/ScriptObservatory/backend/static/img/
    echo "done!"
    
    sleep 43200  # 12h

done

