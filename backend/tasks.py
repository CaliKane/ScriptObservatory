import datetime
import gzip
import hashlib
import os
import sqlalchemy
import sys

from celery import Celery
from celery.decorators import task
from flask import render_template
import yara

from backend import app, db
from backend.lib import sendmail
from backend.models import Resource, YaraRuleset


def sha256(string):
    return hashlib.sha256(string.encode('utf-8')).hexdigest()


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
    print("got match for {0} - {1} !".format(email, namespace))

    now = datetime.datetime.now()
    matches = []
    
    for hash in hashes:
        record = Resource.query.filter(Resource.hash == hash).limit(app.config['MAX_PAGES_PER_HASH']).all() 
        urls = [{'webpage_url': r.pageview.url, 'webpage_hash': sha256(r.pageview.url), 'resource_url': r.url} for r in record]
        new_match = {'hash': hash, 'urls': urls}
        matches.append(new_match)

    rule = YaraRuleset.query.filter_by(email=email, namespace=namespace).first()
    
    if rule.email_tokens is None: 
        rule.email_tokens = 5
    
    print("email tokens = {}".format(rule.email_tokens))

    if rule.last_received_tokens is None:
        rule.last_received_tokens = now

    print("last rx tokens = {}".format(rule.last_received_tokens))

    rule.email_tokens -= 1
    rule.email_tokens = min(10, rule.email_tokens + (now - rule.last_received_tokens) // datetime.timedelta(minutes=1))
    rule.last_received_tokens = now

    print("at end, email tokens = {}".format(rule.email_tokens))

    sendmail(email, 
             'YARA Scan Results (success!): {}'.format(namespace), 
             render_template('email/yara_match.html', matches=matches, tokens=rule.email_tokens))

    if rule.email_tokens <= 0:
        print("removing rule!")
        sendmail(rule.email,
                 'YARA Rule Removed ({})'.format(rule.namespace),
                  render_template('email/yara_goodbye.html', rule=rule))

        db.session.delete(rule)

    db.session.commit()


@task(time_limit=3600)
def yara_retroscan_for_rule(rule_id):
    rule = YaraRuleset.query.filter_by(id=rule_id).one()
    sources = {rule.namespace: rule.source}

    try:
        yara_rule = yara.compile(sources=sources)
    except:
        # TODO: this should never happen, so this email should go to the site admin
        sendmail(rule.email, 'YARA Retroscan Results (error in rule compilation!)', render_template('email/yara_error.html'))
        return

    os.nice(5)
    matches = []
    try:
        for subdir in os.listdir(app.config['RESOURCE_CONTENT_FOLDER']):
            try:
                subdir = os.path.join(app.config['RESOURCE_CONTENT_FOLDER'], subdir)
                for path in os.listdir(subdir):
                    with gzip.open(os.path.join(subdir, path), 'rb') as f:
                        if yara_rule.match(data=f.read()):
                            matches.append(path.split('.')[0]) 
                            if len(matches) > app.config['MAX_HASHES']:
                                break
            except NotADirectoryError:
                pass
    except:
        sendmail(rule.email, 'YARA Retroscan Error ({0})'.format(sys.exc_info()), render_template('email/yara_error.html'))
    else:
        yara_report_matches.apply_async(args=(rule.email, rule.namespace, matches))
    
    os.nice(0)


@task
def yara_scan_file_for_email(email, path):
    # TODO: filter for 'scan_on_upload==True' too
    # TODO: store compiled rules in database to avoid re-compiling?
    try:
        rulesets = YaraRuleset.query.filter_by(email=email).all()
        sources = {}
        
        for r in rulesets:
            sources[r.namespace] = r.source

        def matchcb(data):
            if data['matches']:
                yara_report_matches.apply_async(args=(email, 
                                                      data['namespace'], 
                                                      [path.split('/')[-1].split('.')[0]]), 
                                                countdown=10)
            return yara.CALLBACK_CONTINUE

        # TODO: these "except" clauses should be consolidated and should catch
        #       specific exceptions.
        try:
            rules = yara.compile(sources=sources)
            
            with gzip.open(path, 'rb') as f:
                try:
                    rules.match(data=f.read(), callback=matchcb)
    
                except:
                    # TODO: this should never happen, so this email should 
                    #       go to the site admin
                    sendmail('scriptobservatory@gmail.com',
                             'YARA Livescan Results (error while reading file / matching ruleset!)',
                             render_template('email/yara_error.html'))

        except:
            # TODO: this should never happen, so this email should go to the site admin
            sendmail('scriptobservatory@gmail.com', 
                     'YARA Scan Results (error in rule compilation!)', 
                     render_template('email/yara_error.html'))


    except (sqlalchemy.exc.DatabaseError, sqlalchemy.exc.OperationalError) as exc:
        print("retrying....")
        #raise yara_scan_file_for_email.retry(exc=exc)


@task
def yara_scan_file(path):
    print(path)
    emails = YaraRuleset.query.with_entities(YaraRuleset.email).group_by(YaraRuleset.email).all()
    for email in emails:
        yara_scan_file_for_email.delay(email[0], path)

