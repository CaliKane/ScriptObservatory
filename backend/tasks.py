import gzip
import os
import yara
from backend import app
from backend.lib import sendmail
from celery import Celery
from celery.decorators import task
from flask import render_template
from backend.models import Script, YaraRuleset

#
# notes:
# launch celery worker with "celery -A backend.tasks.celery worker --loglevel=info" from root project dir
#

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
def yara_report_matches(email, namespace, hashes):
    matches = []
    for hash in hashes:
        record = Script.query.filter(Script.hash == hash).limit(app.config['MAX_PAGES_PER_HASH']).all() 
        record_urls = list(set([s.pageview.url for s in record]))  # uniq-ify with set()
        new_match = {'hash': hash, 'unique_urls': record_urls}
        matches.append(new_match)

    sendmail(email, 
             "YARA Scan Results (success!): {}".format(namespace), 
             render_template('email/yara_match.html', matches=matches))


@task(time_limit=3600)
def yara_retroscan_for_rule(rule_id):
    rule = YaraRuleset.query.filter_by(id=rule_id).all()[0]
    sources = {rule.namespace: rule.source}

    try:
        yara_rule = yara.compile(sources=sources)
    except:
        sendmail(rule.email, "YARA Retroscan Results (error in rule compilation!)", render_template('email/yara_error.html'))
    
    os.nice(5)

    matches = []
    try:
        for path in os.listdir(app.config['SCRIPT_CONTENT_FOLDER']):
            with gzip.open(os.path.join(app.config['SCRIPT_CONTENT_FOLDER'], path), 'rb') as f:
                if yara_rule.match(data=f.read()):
                    matches.append(path.split('.')[0]) 
                    if len(matches) > app.config['MAX_HASHES']:
                        break
    except:
        sendmail(rule.email, "YARA Retroscan Results (error while scanning!)", render_template('email/yara_error.html'))
    else:
        yara_report_matches.apply_async(args=(rule.email, rule.namespace, matches), countdown=60)
    
    os.nice(0)


@task
def yara_scan_file_for_email(email, path):
    sources = {}
    # TODO: filter for "scan_on_upload==True" too
    rulesets = YaraRuleset.query.filter_by(email=email).all()
    for r in rulesets:
        sources[r.namespace] = r.source

    def matchcb(data):
        if data['matches']:
            yara_report_matches.apply_async(args=(email, data['namespace'], [path.split('/')[-1].split('.')[0]]), countdown=60)
        return yara.CALLBACK_CONTINUE

    try:
        # TODO: store compiled rules in database to avoid re-compiling?
        rules = yara.compile(sources=sources)
    except:
        sendmail(email, "YARA Scan Results (error!)", render_template('email/yara_error.html'))

    with gzip.open(path, 'rb') as f:
        try:
            rules.match(data=f.read(), callback=matchcb)
        except:
            sendmail(email, "YARA Scan Results (error!)", render_template('email/yara_error.html'))


@task
def yara_scan_file(path):
    emails = YaraRuleset.query.with_entities(YaraRuleset.email).group_by(YaraRuleset.email).all()
    for email in emails:
        yara_scan_file_for_email.delay(email[0], path)
