from backend import db


class Webpage(db.Model):
    __tablename__ = "webpage"
    id = db.Column(db.Text, primary_key=True)
    url = db.Column(db.Text, unique=True)
    pageviews = db.relationship("Pageview", backref="webpage", lazy='subquery')


class Pageview(db.Model):
    __tablename__ = "pageview"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Integer, db.ForeignKey("webpage.url"))
    date = db.Column(db.Integer, unique=False)
    scripts = db.relationship("Script", backref=db.backref("pageview", lazy='subquery'), lazy='subquery')
    
    def __init__(self, **kwargs):
        super(Pageview, self).__init__(**kwargs)
        self.date = int(1000*time.time())


class Script(db.Model):
    __tablename__ = "script"
    id = db.Column(db.Integer, primary_key=True)
    pageview_id = db.Column(db.Integer, db.ForeignKey("pageview.id"))
    url = db.Column(db.Text, unique=False)
    hash = db.Column(db.Text, unique=False)


class RoboTask(db.Model):
    __tablename__ = "robotask"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.Text, unique=False)
    priority = db.Column(db.Integer, unique=False)


class Suggestions(db.Model):
    __tablename__ = "suggestions"
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, unique=False)


class YaraRuleset(db.Model):
    __tablename__ = "yara_ruleset"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.Unicode(255))
    namespace = db.Column(db.Unicode(255))
    source = db.Column(db.UnicodeText)
