#!/usr/bin/env python3
#

from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy

from backend import config


app = Flask(__name__, static_url_path='')
app.config.from_object(config)

db = SQLAlchemy(app)
db.create_all()

