#!/bin/bash
#

export PATH_TO_EXTENSION=/home/andy/projects/ScriptObservatory/chrome-extension/
Xvfb :1 -screen 0 1024x768x24 2>&1 > /dev/null &
export DISPLAY=:1
