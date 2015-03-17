#!/usr/bin/env python2
#

import os
import ssl

from flask import Flask
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, Text


context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(os.environ['TLS_CRT_PATH'], os.environ['TLS_KEY_PATH'])

app = Flask(__name__, static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)

class Script(db.Model):
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=False)
    parent_url = Column(Text, unique=False)
    sha256 = Column(Text, unique=False)
    date = Column(Integer, unique=False)    

db.create_all()

api_manager = APIManager(app, flask_sqlalchemy_db=db)
api_manager.create_api(Script,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

@app.route('/')
def index():
    return app.send_static_file("index.html")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=443, ssl_context=context, use_reloader=False)


