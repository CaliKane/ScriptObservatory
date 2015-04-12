#!/usr/bin/env python2
#

from flask import Flask
from flask.ext.restless import APIManager
from flask.ext.sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import Column, Integer, Text, ForeignKey, create_engine


app = Flask(__name__, static_url_path='')
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"
db = SQLAlchemy(app)


class Pageview(db.Model):
    __tablename__ = "pageview"
    id = Column(Integer, primary_key=True)
    url = Column(Text, unique=False)
    date = Column(Integer, unique=False)    
    scripts = relationship("Script")

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

class ScriptContent(db.Model):
    __tablename__ = "scriptcontent"
    sha256 = Column(Text, primary_key=True)
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
api_manager.create_api(Script,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])

api_manager.create_api(Pageview,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])

api_manager.create_api(RoboTask,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

api_manager.create_api(ScriptContent,
                       max_results_per_page=0,
                       methods=["GET", "POST", "DELETE", "PUT"])

api_manager.create_api(ScriptUrlIndex,
                       max_results_per_page=0,
                       methods=["GET"])

api_manager.create_api(ScriptHashIndex,
                       max_results_per_page=0,
                       methods=["GET"])


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
    app.run(host="0.0.0.0", port=8080, use_reloader=False)

