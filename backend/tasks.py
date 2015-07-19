import gzip
import os.path
import yara
from backend import app
from backend.lib import sendmail
from celery import Celery
from celery.decorators import task
from flask import render_template
from backend.models import Script, YaraRuleset


def make_celery(app):
    celery = Celery(app.import_name, broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)

    celery.Task = ContextTask
    return celery


celery = make_celery(app)


@task
def yara_report_match(email, path, data):
    hash = path.split('.')[0]
    scripts = Script.query.\
            filter(Script.hash == hash).limit(
        app.config['MAX_PAGES_PER_HASH']).all()

    sendmail(
        email,
        "YARA Scan Results (success!): {}".format(data['namespace']),
        render_template('email/yara_match.html', hash=hash, scripts=scripts))


@task
def yara_scan_file_for_email(email, path):
    sources = {}
    rulesets = YaraRuleset.query.filter_by(email=email).all()
    for r in rulesets:
        sources[r.namespace] = r.source

    def matchcb(data):
        if data['matches']:
            yara_report_match.delay(email, path, data)
        return yara.CALLBACK_CONTINUE

    try:
        rules = yara.compile(sources=sources)
    except:
        sendmail(
            email,
            "YARA Scan Results (error!)",
            render_template('email/yara_error.html'))

    with gzip.open(
            os.path.join(app.config['SCRIPT_CONTENT_FOLDER'], path),
            'rb') as f:
        try:
            rules.match(data=f.read(), callback=matchcb)
        except:
            sendmail(
                email,
                "YARA Scan Results (error!)",
                render_template('email/yara_error.html'))


@task
def yara_scan_file(path):
    emails = YaraRuleset.query.with_entities(YaraRuleset.email).\
            group_by(YaraRuleset.email).all()
    for email in emails:
        yara_scan_file_for_email.delay(email[0], path)
