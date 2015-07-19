#!/usr/bin/env python3
#
# This code implements all backend functionality, including database models, database 
# management, advanced data querying, and script-content file serving.
#
# NOTES on speeding up queries....
#   Table indices need to be manually created until code is added to do this directly 
#   with flask/SQLAlchemy. Information here describes the command you need to run:
#
#        https://www.sqlite.org/lang_createindex.html
#
#   Thanks Micah for the pointers! :) https://github.com/macro1
#

import json
import os
import hashlib
import sys
import time
from threading import Thread

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

from backend import config


app = Flask(__name__, static_url_path='')
app.config.from_object(config)
db = SQLAlchemy(app)


from backend import models
db.create_all()

from backend import views
