#!/usr/bin/env python3
#
# This code implements all backend functionality, including database models, database 
# management, advanced data querying, and script-content file serving.

# NOTES on speeding up queries....
#   Table indices need to be manually created until code is added to do this directly 
#   with flask/SQLAlchemy. Information here describes the command you need to run:
#
#        https://www.sqlite.org/lang_createindex.html
#
#    Thanks Micah for the pointers! :) https://github.com/macro1
#

import json
import os
import hashlib
import sys
import time

from flask import Flask, request, jsonify, send_from_directory
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import Column, Integer, Text, ForeignKey


SCRIPT_CONTENT_FOLDER = os.environ['PATH_TO_STORE_SCRIPTCONTENT']

app = Flask(__name__, static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)


class Webpage(db.Model):
    __tablename__ = "webpage"
    id = Column(Text, primary_key=True)
    url = Column(Text, unique=True)
    pageviews = relationship("Pageview", backref="webpage", lazy='subquery')

class Pageview(db.Model):
    __tablename__ = "pageview"
    id = Column(Integer, primary_key=True)
    url = Column(Integer, ForeignKey("webpage.url"))
    date = Column(Integer, unique=False)
    scripts = relationship("Script", backref=db.backref("pageview", lazy='subquery'), lazy='subquery')
    
    def __init__(self, **kwargs):
        super(Pageview, self).__init__(**kwargs)
        self.date = int(1000*time.time())

class Script(db.Model):
    __tablename__ = "script"
    id = Column(Integer, primary_key=True)
    pageview_id = Column(Integer, ForeignKey("pageview.id"))
    url = Column(Text, unique=False)
    hash = Column(Text, unique=False)

class RoboTask(db.Model):
    __tablename__ = "robotask"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=False)
    priority = Column(Integer, unique=False)

class Suggestions(db.Model):
    __tablename__ = "suggestions"
    id = Column(Integer, primary_key=True)
    content = Column(Text, unique=False)


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

api_manager.create_api(Suggestions,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])


@app.route('/script-content/<path:filename>', methods=["GET"])
def get_script_content(filename):
    return send_from_directory(SCRIPT_CONTENT_FOLDER, "{0}.txt".format(filename), as_attachment=False)


@app.route('/script-content', methods=["POST"])
def post_script_content():
    # first we check to see if the file exists for the hash the client provides 
    # (let's avoid spending the effort to hash the user's data in the 99% case 
    # where the user isn't lying. we'll eventually check their hash later)
    req = json.loads(str(request.data, 'utf-8'))
    sha256_c = req.get('sha256')
    filename = os.path.join(SCRIPT_CONTENT_FOLDER, '{0}.txt'.format(sha256_c))
    
    if os.path.isfile(filename):
        return 'we already have this content'

    # we double check that the hash we've calculated matches the hash provided by the client
    # and then write the file to disk
    content = req.get('content')
    sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
    
    if sha256_c != sha256:
        # TODO: auto-report cases where this check fails? this should never happen
        return "content / hash mismatch"

    filename = os.path.join(SCRIPT_CONTENT_FOLDER, '{0}.txt'.format(sha256))
    with open(filename, 'wb') as f:
        f.write(content.encode('utf-8'))

    return 'thanks!'
    # TODO: eventually, we can have the chrome extension track hashes the server already has
    # and not try to upload them to save bandwidth.


@app.route('/search', methods=["GET"])
def search():
    url = request.args.get('url')
    url_hash = request.args.get('hash')
    script_by_url = request.args.get('script_by_url')
    script_by_hash = request.args.get('script_by_hash')

    if not any([url, url_hash, script_by_url, script_by_hash]):
        return "enter a query parameter! {url, hash, script_by_url, script_by_hash}"

    json = {'objects': []}
    
    if url_hash or url:
        if url_hash is not None:
            websites = [db.session.query(Webpage).get(url_hash)]
        elif url is not None:   
            websites = db.session.query(Webpage).filter(Webpage.url.contains(url)).all()
        
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

            json['objects'].append(json_site)    
    
    elif script_by_url or script_by_hash:
        if script_by_url is not None:   
            scripts = db.session.query(Script).filter(Script.url == script_by_url).all()
        elif script_by_hash is not None:   
            scripts = db.session.query(Script).filter(Script.hash == script_by_hash).all()
        
        json['objects'] = list(set([s.pageview.url for s in scripts]))  # de-dup with set()

    return jsonify(json)


@app.route('/')
def index():
    return app.send_static_file("index.html")

if __name__ == '__main__':
    port = int(os.environ['BACKEND_PORT'])
    app.run(host="0.0.0.0", port=port, use_reloader=False)

