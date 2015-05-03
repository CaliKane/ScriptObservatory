#!/usr/bin/env python3
#

import time

from flask import Flask, request, jsonify
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, Text, ForeignKey


app = Flask(__name__, static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)


class Webpage(db.Model):
    __tablename__ = "webpage"
    id = Column(Text, primary_key=True)
    url = Column(Text, unique=True)
    pageviews = relationship("Pageview", backref="webpage", lazy="joined")

class Pageview(db.Model):
    __tablename__ = "pageview"
    date = Column(Integer, primary_key=True)
    webpage_url = Column(Integer, ForeignKey("webpage.url"))
    scripts = relationship("Script", backref="pageview", lazy="joined")
    
    def __init__(self, **kwargs):
        super(Pageview, self).__init__(**kwargs)
        self.date = int(1000*time.time())

class Script(db.Model):
    __tablename__ = "script"
    id = Column(Integer, primary_key=True)
    pageview_id = Column(Integer, ForeignKey("pageview.date"))
    url = Column(Text, unique=False)
    hash = Column(Text, unique=False)

class RoboTask(db.Model):
    __tablename__ = "robotask"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=False)
    priority = Column(Integer, unique=False)

class ScriptContent(db.Model):
    __tablename__ = "scriptcontent"
    sha256 = Column(Text, primary_key=True)
    content = Column(Text, unique=False)

class Suggestions(db.Model):
    __tablename__ = "suggestions"
    id = Column(Integer, primary_key=True)
    content = Column(Text, unique=False)

class ScriptUrlIndex(db.Model):
    __tablename__ = "scripturlindex"
    script_url = Column(Text, primary_key=True)
    page_urls = Column(Text, unique=False)  # comma-separated list of URLs

class ScriptHashIndex(db.Model):
    __tablename__ = "scripthashindex"
    script_hash = Column(Text, primary_key=True)
    page_urls = Column(Text, unique=False)  # comma-separated list of URLs


db.create_all()

api_manager = APIManager(app, flask_sqlalchemy_db=db)
api_manager.create_api(Webpage,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT", "PATCH"])

api_manager.create_api(Pageview,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT", "PATCH"])

api_manager.create_api(Script,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT", "PATCH"])

api_manager.create_api(RoboTask,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

api_manager.create_api(ScriptContent,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])

api_manager.create_api(ScriptUrlIndex,
                       max_results_per_page=0,
                       methods=["GET"])

api_manager.create_api(ScriptHashIndex,
                       max_results_per_page=0,
                       methods=["GET"])

api_manager.create_api(Suggestions,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])


@app.route('/search', methods=["GET"])
def search():
    url = request.args.get('url')
    
    if id is None:
        return "enter a ?url=___ parameter!"

    # to do an exact query --> query(Webpage).get(__primary_key__).all()
    websites = db.session.query(Webpage).filter(Webpage.url.contains(url)).all()
    json = {'sites': []}

    for site in websites:
        json_site = {}
        json_site['url'] = site.url
        json_site['id'] = site.id
        json_site['pageviews'] = []

        for pv in site.pageviews:
            json_pv = {}
            json_pv['date'] = pv.date
            json_pv['scripts'] = []

            for script in pv.scripts:
                json_script = {}
                json_script['url'] = script.url
                json_script['hash'] = script.hash
                json_pv['scripts'].append(json_script)

            json_site['pageviews'].append(json_pv)

        json['sites'].append(json_site)    

    return jsonify(json)


@app.route('/')
def index():
    return app.send_static_file("index.html")

if __name__ == '__main__':
    app.debug = True
    app.run(host="0.0.0.0", port=8080, use_reloader=False)

