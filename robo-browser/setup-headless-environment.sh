#!/bin/bash
#
# run this script before launching robo-browser.py to have the robo-browser run
# headlessly (ie over a ssh connection)
#
# requires:
#  - xvfb 
#

export PATH_TO_EXTENSION=/home/andy/projects/ScriptObservatory/chrome-extension/
Xvfb :1 -screen 0 1024x768x24 2>&1 > /dev/null &
export DISPLAY=:1
