#!/usr/bin/env python2
#

from flask import Flask
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy import Column, Integer, Text


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
    app.debug = True
    app.run(host="127.0.0.1", port=8080, use_reloader=False)


