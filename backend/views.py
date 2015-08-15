import datetime
import functools
import gzip
import hashlib
import html
import json
import os
import re
import requests
import sys
import time
from operator import itemgetter
from urllib.parse import urlparse

from flask import flash, jsonify, redirect, render_template, request, \
    send_from_directory, url_for
from flask.ext.restless import APIManager
import yara

import backend
from backend import app
from backend import db
from backend.models import Webpage, Pageview, Resource, RoboTask, Suggestions, \
    YaraRuleset
from backend.tasks import yara_scan_file
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'external'))
import external.jsbeautifier


def verify_ip_is_authorized(**kw):
    """ check to see if the request's IP is in the whitelist. If it's not, report
        the IP to the suggestions API (for now) and don't let the request proceed """
    if app.config['API_IP_WHITELIST_ENABLED']:
        if request.remote_addr not in app.config['API_IP_WHITELIST']:
            report = {'content': 'Rx strange requests from {}'.format(request.remote_addr)}
   
            r = requests.post('https://scriptobservatory.org/api/suggestions',
                              data=json.dumps(report),
                              headers={'content-type': 'application/json'},
                              verify=False)

            raise ProcessingException(description='Not Authorized',
                                      code=401)
 

def get_resource_content_location(hash):
    """ get the resource content directory and filename for a given hash value """ 
    directory = os.path.join(app.config['RESOURCE_CONTENT_FOLDER'], hash[0:4])
    f = os.path.join(directory, hash)
    return directory, '{0}.txt.gz'.format(f)


def date_collision_present(list_a, list_b):
    """ detect if any two objects from two different lists contain the same 'date'
        (helper function for resource alignment algorithm) """ 
    for a in list_a:
        for b in list_b:
            if a['date'] == b['date']:
                return True
    return False


def view_list_sorter(a, b):
    """ custom sorting algorithm for experimental resource visualization """
    # put inline_scripts_ last by default
    if a['name'].startswith('inline_script_') and not b['name'].startswith('inline_script_'): return 1
    elif b['name'].startswith('inline_script_') and not a['name'].startswith('inline_script_'): return -1

    # then put those with the most entries towards the top
    if a['total'] > b['total']: return -1
    elif b['total'] > a['total']: return 1
    
    # then try to put those with more recent "last seen" dates towards the top
    if a['views'][-1]['date'] > b['views'][-1]['date']: return -1
    elif b['views'][-1]['date'] > a['views'][-1]['date']: return 1

    return 0


@backend.csrf.include
@app.route('/yara', methods=['GET', 'POST'])
def yara_index():
    errors = []

    if request.method == 'POST':
        email = request.form['email'].strip()
        if len(email) <= 0:
            errors.append("You must provide an email address")
        elif email not in app.config['EMAIL_WHITELIST']:
            errors.append("Email address not in whitelist")

        namespace = request.form['namespace'].strip()
        if len(namespace) <= 0:
            errors.append("You must provide a namespace")
        else:
            dups = YaraRuleset.query.filter_by(email=email,
                                               namespace=namespace).count()
            if dups > 0:
                errors.append("The namespace you have provided has already "
                              "been used for that email address. Please "
                              "choose a new one.")

        source = request.form['source'].strip()
        if len(source) <= 0:
            errors.append("You must provide some Yara rules")

        try:
            if len(errors) <= 0:
                ruleset = YaraRuleset(email, namespace, source, True)
                db.session.add(ruleset)
                db.session.commit()

                flash("Rules successfully added!")
                time.sleep(2)
                return redirect(url_for('yara_index'))
        
        except yara.libyara_wrapper.YaraSyntaxError as e:
            errors.append("Syntax error in yara rule: {}".format(e))

    return render_template('yara/index.html', errors=errors)


def is_valid_sha256(h, regex=re.compile(r'^[a-f0-9]{64}$').search):
    """ determine if a string *h* is a valid sha256 hash """
    return bool(regex(h))


@app.route('/resource-content/<path:hash>', methods=['GET'])
def get_resource_content(hash, beautify=True):
    # TODO: handle case where it's a 'sub_frame' type instead of 'script'
    _, filename = get_resource_content_location(hash)
    
    content = 'content not found'
    if os.path.isfile(filename):
        with gzip.open(filename, 'rb') as f:
            content = f.read().decode('utf-8')

    if beautify:
        content = external.jsbeautifier.beautify(content, opts)
    else:
        content = html.escape(content)

    return render_template('resource-content/view_script_content.html',
                           scriptcontent=[{'hash': hash, 'content': content}],
                           beautified=beautify)


@app.route('/api/resource-content', methods=['GET'])
def resource_content_api_get():
    """ GET Parameters for API:
        *mandatory* 
        - hashes = list of hashes --> returns true/false values for if each hash
                                      is already present & stored on disk.

        *optional*
        - content = True - -> causes API to return full content of resources 
        - beautify = True --> causes API to return beautified JS content """

    hash_list = request.args.get('hashes').split(',')
    beautify = True if request.args.get('beautify') == 'true' else False
    return_content = True if beautify or request.args.get('content') == 'true' else False
    
    response = {}
    for sha256 in hash_list:
        if not is_valid_sha256(sha256):
            # TODO: auto-report these?
            return 'invalid hash'

        _, filename = get_resource_content_location(sha256)
        content = 'false'
        if os.path.isfile(filename):
            if return_content:
                with gzip.open(filename, 'rb') as f:
                    content = f.read().decode('utf-8')
                    if not beautify:
                        content = html.escape(content)
            else:
                content = 'true'
        response[sha256] = content

    if beautify:
        template_content = []
        for sha256 in response.keys():
            c = response[sha256]
            if beautify: c = external.jsbeautifier.beautify(c, opts)
            template_content.append({'hash': sha256, 'content': c})

        # TODO: handle 'sub_frame' type too
        return render_template('resource-content/view_script_content.html',
                               scriptcontent=template_content,
                               beautified=beautify)
    else:
        return jsonify(response)


@app.route('/api/resource-content', methods=['POST'])
def resource_content_api_post():
    """ POST API takes objects like:
            {"upload": [{"sha256": "abcd01234abcd01234abcd01234abcd01234",
                         "content": "... content goes here ..."},
                        {"sha256": "5678efab5678efab5678efab5678efab5678",
                         "content": "... 2nd content here ..."},
                                             . .  
                                             . .  
                                         . . . . . . 
                                           . etc .  
                                             . .  
                                              .
                       ]} 
        
        Misc Notes:
          - SHA256 hashes are verified server-side
          - Request source IP must be on the whitelist  """
    
    # check to see if it's coming from an authorized IP address:
    verify_ip_is_authorized()

    # first we check to see if the file exists for the hash the client provides 
    # (let's avoid spending the effort to hash the user's data in the 99% case 
    # where the user isn't lying. we'll eventually check their hash later)
    req = json.loads(str(request.data, 'utf-8'))
    upload_list = req.get('upload')
    response = {}

    for data in upload_list:
        sha256_c = data.get('sha256')
        filedir, filename = get_resource_content_location(sha256_c)
        
        if os.path.isfile(filename):
            response[sha256_c] = 'false'
            break

        # we double check that the hash we've calculated matches the hash provided
        # by the client and then write the file to disk
        content = data.get('content')
        sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        if sha256_c != sha256:
            # TODO: auto-report cases where this check fails? 
            return 'content / hash mismatch'

        os.makedirs(filedir, exist_ok=True)
        with gzip.open(filename, 'wb') as f:
            f.write(content.encode('utf-8'))

        yara_scan_file.delay(filename)
        response[sha256_c] = 'true'
    
    return jsonify(response)


@app.route('/api/search', methods=['GET'])
def search_api():
    """ The search API is the main code used by the frontend UI to get the data it needs
        to fill out its display & calculate the needed stats. Should eventually be broken
        up when the new UI is implemented. """
        
    url = request.args.get('url')
    url_hash = request.args.get('hash')
    resource_by_url = request.args.get('resource_by_url')
    resource_by_hash = request.args.get('resource_by_hash')

    if not any([url, url_hash, resource_by_url, resource_by_hash]):
        return 'enter a query parameter! {url, hash, resource_by_url, resource_by_hash}'

    json = {'objects': []}
 
    if url_hash or url:
        if url_hash is not None:
            websites = [db.session.query(Webpage).get(url_hash)]
        elif url is not None:
            # temp hack: check first to see the total # of webpages returned. if it >= MAX_WEBPAGE_RESULTS, don't run the query..
            websites = db.session.query(Webpage).filter(Webpage.url.contains(url)).limit(app.config['MAX_WEBPAGE_RESULTS']).all()
            if len(websites) >= app.config['MAX_WEBPAGE_RESULTS']:
                time.sleep(60)
                return json
            
            websites = db.session.query(Webpage).filter(Webpage.url.contains(url)).all()

        for site in websites:
            json_site = {}
            json_site['url'] = site.url
            json_site['id'] = site.id
            json_site['pageviews'] = []

            for pv in site.pageviews:
                json_pv = {}
                json_pv['date'] = pv.date
                json_pv['resources'] = []

                for script in pv.resources:
                    json_script = {}
                    json_script['url'] = script.url
                    json_script['hash'] = script.hash
                    json_pv['resources'].append(json_script)

                json_site['pageviews'].append(json_pv)

            json['objects'].append(json_site)    
    
    elif resource_by_url or resource_by_hash:
        if resource_by_url is not None:   
            resources = db.session.query(Resource).filter(Resource.url == resource_by_url).limit(app.config['MAX_RESOURCE_RESULTS']).all()
        elif resource_by_hash is not None:   
            resources = db.session.query(Resource).filter(Resource.hash == resource_by_hash).limit(app.config['MAX_RESOURCE_RESULTS']).all()
        
        json['objects'] = list(set([r.pageview.url for r in resources]))
    
    return jsonify(json)


@app.route('/api/get_aligned_data', methods=['GET'])
def align_webpage_data():
    """ Code for the experimental visualization. This should be used as a starting point for
        the new UI and should eventually be pulled out of the /api/ path. """ 
    
    def exp_filter(resources, eval_condition, eval_rekey):
        """ Helper function that combines two resource lists if there's no date collision and 
            *eval_condition* is met. The *resources* dict is rekeyed with *eval_rekey* after
            processing is finished.
            
            WARNING: neither *eval_condition* or *eval_rekey* should ever be user-controlled! """

        new_resources = {}
        for k in resources.keys():
            placed = False
            for new_k in new_resources.keys():
                if eval(eval_condition) and not date_collision_present(resources[k], new_resources[new_k]):
                    new_key = eval(eval_rekey)
                    new_val = resources[k] + new_resources[new_k]
                    del new_resources[new_k]
                    new_resources[new_key] = new_val
                    placed = True
                    break

            if placed == False:
                new_resources[resources[k][0]['url']] = resources[k]
        
        return new_resources

    url = request.args.get('url')
    if not url: return 'please supply a URL parameter'
    
    webpage = Webpage.query.filter(Webpage.url == url).one()

    ## Pull out all relevant resources
    FIRST_T = False
    resources = {}
    i = 0
    for pv in webpage.pageviews:
        for r in pv.resources:
            resources[str(i)] = [{'url': r.url, 
                            'hash': r.hash, 
                            'parent_url': r.pageview.url, 
                            'date': pv.date}]
            
            i += 1

        if not FIRST_T or pv.date < FIRST_T:
            FIRST_T = pv.date
    
    ##
    ## Align our resources as best we can
    ## (order- equal urls, equal filenames, equal hash values, equal subdomains & paths, collapse inline_scripts as much as possible)
    ##
    ## TODO: do matching against *any*, not just first entry 
    ## TODO: clean and only define one side of the equals sign
    ##
    resources = exp_filter(resources, 
                           "new_resources[new_k][0]['url'] == resources[k][0]['url']", 
                           "new_k")

    resources = exp_filter(resources,   
                           "urlparse(resources[k][0]['url']).path.split('/')[-1] == urlparse(new_resources[new_k][0]['url']).path.split('/')[-1]", 
                           "urlparse(resources[k][0]['url']).path.split('/')[-1]")
    
    resources = exp_filter(resources,
                           "new_resources[new_k][0]['hash'] == resources[k][0]['hash']",
                           "new_resources[new_k][0]['hash']")

    resources = exp_filter(resources,
                           "not resources[k][0]['url'].startswith('inline_script_') and new_resources[new_k][0]['url'].split('/')[:-1] == resources[k][0]['url'].split('/')[:-1]",
                           "'Resource from {0}'.format(urlparse(new_resources[new_k][0]['url']).netloc)")
     
    resources = exp_filter(resources,
                           "resources[k][0]['url'].startswith('inline_script_') and new_resources[new_k][0]['url'].startswith('inline_script_')",
                           "'inline_script_*'")
    
    ## Reduce to expected JSON format
    final_resources = []
    for ind, key in enumerate(resources.keys()):
        # scale our time values to a relative scale
        for view in resources[key]: 
            view['date'] = (view['date'] - FIRST_T).days
        
        # because we plot one dot per day and we may have multiple views of a given resource on one day, we
        # need to go through and consolidate those views, increasing 'n' when we have more than one occurrance
        view_list = []
        for view in resources[key]:
            try:
                i = list(map(itemgetter('date'), view_list)).index(view['date'])
                view_list[i]['n'] += 1
                view_list[i]['details'].append({'url': view['url'],
                                                'hash': view['hash']})
            except ValueError:
                view_list.append({'date': view['date'], 
                                  'n': 1, 
                                  'details': [{'url': view['url'], 
                                               'hash': view['hash']}]})

        final_resources.append({'name': key,
                                'views': view_list,
                                'total': len(resources[key])})

    first_t_in_days_ago = (datetime.datetime.now() - FIRST_T).days

    ## Sort & return final_resources
    final_resources = sorted(final_resources, key=functools.cmp_to_key(view_list_sorter))
    return render_template('visualizations/aligned_scripts.html',
                           json_data=json.dumps(final_resources),
                           first_t_in_days_ago=first_t_in_days_ago)


@app.route('/')
def index():
    return app.send_static_file('index.html')


@app.route('/search/')
def search():
    """ this is a temporary hack to let us serve query links that end in ?query=XXX off of
        a path that's been added to the robots.txt file to prevent google from indexing them """
    return app.send_static_file('index.html')


opts = external.jsbeautifier.default_options()
opts.unescape_strings = True
opts.eval_code = True

api_manager = APIManager(app, flask_sqlalchemy_db=db)
api_manager.create_api(Webpage,
                       max_results_per_page=0,
                       methods=['GET', 'POST', 'PUT', 'PATCH'],
                       preprocessors={
                           'POST': [verify_ip_is_authorized],
                           'PATCH_SINGLE': [verify_ip_is_authorized],
                           'PATCH_MANY': [verify_ip_is_authorized],
                           'PUT_SINGLE': [verify_ip_is_authorized],
                           'PUT_MANY': [verify_ip_is_authorized]
                       })

api_manager.create_api(Pageview,
                       max_results_per_page=0,
                       methods=['GET', 'POST', 'PUT', 'PATCH'],
                       preprocessors={
                           'POST': [verify_ip_is_authorized],
                           'PATCH_SINGLE': [verify_ip_is_authorized],
                           'PATCH_MANY': [verify_ip_is_authorized],
                           'PUT_SINGLE': [verify_ip_is_authorized],
                           'PUT_MANY': [verify_ip_is_authorized]
                       })

api_manager.create_api(Resource,
                       max_results_per_page=0,
                       methods=['GET', 'POST', 'PUT', 'PATCH'],
                       preprocessors={
                           'POST': [verify_ip_is_authorized],
                           'PATCH_SINGLE': [verify_ip_is_authorized],
                           'PATCH_MANY': [verify_ip_is_authorized],
                           'PUT_SINGLE': [verify_ip_is_authorized],
                           'PUT_MANY': [verify_ip_is_authorized]
                       })

api_manager.create_api(RoboTask,
                       results_per_page=100,
                       methods=['GET', 'POST', 'DELETE', 'PUT'],
                       preprocessors={
                           'DELETE': [verify_ip_is_authorized],
                       })

api_manager.create_api(Suggestions,
                       max_results_per_page=0,
                       methods=['GET', 'POST', 'PUT'])

