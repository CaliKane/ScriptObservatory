#!/usr/bin/env python2
#

import os
import ssl

from flask import Flask
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import Column, Integer, Text, ForeignKey, create_engine


context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(os.environ['TLS_CRT_PATH'], os.environ['TLS_KEY_PATH'])
context.set_ciphers("EECDH:EDH:AESGCM:HIGH:!eNULL:!aNULL:!RC4")
context.options |= ssl.OP_NO_COMPRESSION

app = Flask(__name__, static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)

#class Webpage(db.Model):
#    __tablename__ = "webpage"
#    url = Column(Text, primary_key=True)
#    pageviews = relationship("Pageview")

class Pageview(db.Model):
    __tablename__ = "pageview"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=False)
#    url = Column(Text, ForeignKey("webpage.url"))
    date = Column(Integer, unique=False)    
    scripts = relationship("Script")

class Script(db.Model):
    __tablename__ = "script"
    id = Column(Integer, primary_key=True)
    pageview_id = Column(Integer, ForeignKey("pageview.id"))
    url = Column(Text, unique=False)
    hash = Column(Text, unique=False)

db.create_all()

api_manager = APIManager(app, flask_sqlalchemy_db=db)
api_manager.create_api(Script,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

api_manager.create_api(Pageview,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

#api_manager.create_api(Webpage,
#                       max_results_per_page=0,
#                       methods=["GET", "POST", "DELETE", "PUT"])

@app.after_request
def after_request(response):
    response.headers.add('Strict-Transport-Security', 'max-age=15552000; includeSubDomains; preload')
    response.headers.add('X-Frame-Options', 'SAMEORIGIN')
    return response

@app.route('/')
def index():
    return app.send_static_file("index.html")

@app.route('/api/count_entries')
def count_entries():
    some_engine = create_engine("sqlite:///database.db")
    Session = sessionmaker(bind=some_engine)
    session = Session()

    n_scripts = session.query(Script).count()
    n_pageviews = session.query(Pageview).count()
    return "{0} {1}".format(n_scripts, n_pageviews)


if __name__ == '__main__':
    #app.debug = True
    app.run(host="0.0.0.0", port=443, ssl_context=context, use_reloader=False)


