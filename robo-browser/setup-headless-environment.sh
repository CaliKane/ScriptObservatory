#!/bin/bash
#
# run this script before launching robo-browser.py to have the robo-browser run
# headlessly (ie over a ssh connection)
# 
# command:
#  source setup-headless-environment.sh
#
# requires:
#  Xvfb 
#

Xvfb :1 -screen 0 1024x768x24 2>&1 > /dev/null &
export DISPLAY=:1
