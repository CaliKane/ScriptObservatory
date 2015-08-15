#!/usr/bin/env python3
#

from flask import Flask
from flask.ext.seasurf import SeaSurf
from flask.ext.sqlalchemy import SQLAlchemy

from backend import config

app = Flask(__name__, static_url_path='')
app.config.from_object(config)
csrf = SeaSurf(app)
db = SQLAlchemy(app)

from backend import models 

db.create_all()

from backend import views
