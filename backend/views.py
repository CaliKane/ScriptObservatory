import gzip
import hashlib
import html
import json
import os
import re
import sys
from operator import itemgetter
from urllib.parse import urlparse

from flask import request, jsonify, send_from_directory, render_template
from flask.ext.restless import APIManager

from backend import app
from backend import db
from backend.models import Webpage, Pageview, Script, RoboTask, Suggestions
from backend.tasks import yara_scan_file

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'external'))
import external.jsbeautifier


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
                       results_per_page=100,
                       methods=["GET", "POST", "DELETE", "PUT"])

api_manager.create_api(Suggestions,
                       max_results_per_page=0,
                       methods=["GET", "POST", "PUT"])


@app.route('/yara_scan', methods=["POST"])
def run_yara_scan():
    return "Disabled for now"


def get_script_content_file_path(hash):
    directory = os.path.join(app.config['SCRIPT_CONTENT_FOLDER'], hash[0:4])
    f = os.path.join(directory, hash)
    return directory, "{0}.txt.gz".format(f)


def is_valid_sha256(h, regex=re.compile(r'^[a-f0-9]{64}$').search):
    return bool(regex(h))


@app.route('/script-content/<path:hash>', methods=["GET"])
def get_script_content_pretty(hash):
    return get_script_content(hash, beautify=True)


@app.route('/script-content-raw/<path:hash>', methods=["GET"])
def get_script_content(hash, beautify=False):
    _, filename = get_script_content_file_path(hash)
    
    content = "content not found"
    if os.path.isfile(filename):
        with gzip.open(filename, 'rb') as f:
            content = f.read().decode('utf-8')

    if beautify:
        content = external.jsbeautifier.beautify(content)
    else:
        content = html.escape(content)

    return render_template('script-content/view_script_content.html',
                           scriptcontent=[{'hash': hash, 'content': content}],
                           beautified=beautify)


@app.route('/script-content', methods=["GET"])
def get_script_content_new():
    # API:
    #  Request [beautify = true, hashes = list of hashes] --> beautified view of scriptcontent from all of *hashes*
    #  Request [content = true, hashes = list of hashes] --> map of hash values to the scriptcontent ("false" if not present)
    #  Request [hashes = list of hashes] --> map of hash values to True/False (for if they're already present)
    beautify = True if request.args.get('beautify') == "true" else False
    return_content = True if beautify or request.args.get('content') == "true" else False
    hash_list = request.args.get('hashes').split(',')
    
    response = {}
    for sha256 in hash_list:
        if not is_valid_sha256(sha256):
            # TODO: auto-report these?
            return "invalid hash"

        _, filename = get_script_content_file_path(sha256)
        content = "false"
        if os.path.isfile(filename):
            if return_content:
                with gzip.open(filename, 'rb') as f:
                    content = f.read().decode('utf-8')
                    if not beautify:
                        content = html.escape(content)
            else:
                content = "true"
        response[sha256] = content

    if beautify:
        template_content = []
        for sha256 in response.keys():
            c = response[sha256]
            if beautify: c = external.jsbeautifier.beautify(c)
            template_content.append({'hash': sha256, 'content': c})

        return render_template('script-content/view_script_content.html',
                               scriptcontent=template_content,
                               beautified=beautify)
    else:
        return jsonify(response)


@app.route('/script-content', methods=["POST"])
def post_script_content():
    # first we check to see if the file exists for the hash the client provides 
    # (let's avoid spending the effort to hash the user's data in the 99% case 
    # where the user isn't lying. we'll eventually check their hash later)
    req = json.loads(str(request.data, 'utf-8'))
    upload_list = req.get('upload')
    response = {}

    for data in upload_list:
        sha256_c = data.get('sha256')
        filedir, filename = get_script_content_file_path(sha256_c)
        
        if os.path.isfile(filename):
            response[sha256_c] = "false"
            break

        # we double check that the hash we've calculated matches the hash provided by the client
        # and then write the file to disk
        content = data.get('content')
        sha256 = hashlib.sha256(content.encode('utf-8')).hexdigest()
        
        if sha256_c != sha256:
            # TODO: auto-report cases where this check fails? this should never happen
            return "content / hash mismatch"

        os.makedirs(filedir, exist_ok=True)
        with gzip.open(filename, 'wb') as f:
            f.write(content.encode('utf-8'))

        yara_scan_file.delay(filename)
        response[sha256_c] = "true"
    
    return jsonify(response)


@app.route('/api/search', methods=["GET"])
def api_search():
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
            scripts = db.session.query(Script).filter(Script.url == script_by_url).limit(app.config['MAX_SCRIPT_RESULTS']).all()
        elif script_by_hash is not None:   
            scripts = db.session.query(Script).filter(Script.hash == script_by_hash).limit(app.config['MAX_SCRIPT_RESULTS']).all()
        
        json['objects'] = list(set([s.pageview.url for s in scripts]))  # de-dup with set()

    return jsonify(json)


def date_collision_present(list_a, list_b):
    for a in list_a:
        for b in list_b:
            if a['date'] == b['date']:
                return True
    return False

@app.route('/api/get_aligned_data', methods=["GET"])
def align_webpage_data():
    """ TODO: do matching against *any*, not just first entry in res[] """

    url = request.args.get('url')
    if not url: return "please supply a URL parameter"
    webpage = Webpage.query.filter(Webpage.url == url).one()

    # pull out all relevant script objects
    resources = []
    for pv in webpage.pageviews:
        for s in pv.scripts:
            resources.append({'url': s.url, 'hash': s.hash, 
                             'parent_url': s.pageview.url, 'date': s.pageview.date})     


    ## C1 - line up those with equal hash values
    new_resources = []
    for o in resources:
        placed = False
        for r in new_resources:
            if o['hash'] == r[0]['hash'] and not date_collision_present([o], r):
                r.append(o)
                placed = True
                break
 
        if placed == False:
            new_resources.append([o])
    resources = new_resources

    ## C2 - line up those with equal URLs
    new_resources = []
    for o in resources:
        placed = False
        for r in new_resources:
            if o[0]['url'] == r[0]['url'] and not date_collision_present(o, r):
                r += o
                placed = True
                break

        if placed == False:
            new_resources.append(o)
    resources = new_resources

    ## C3 - line up those with equal filepaths
    new_resources = []
    for o in resources:
        placed = False
        for r in new_resources:
            if urlparse(o[0]['url']).path.split('/')[-1] == urlparse(r[0]['url']).path.split('/')[-1] and not date_collision_present(o, r):
                r += o
                placed = True
                break

        if placed == False:
            new_resources.append(o)
    resources = new_resources

    ## C4 - line up those with equal subdomains & paths
    new_resources = []
    for o in resources:
        placed = False
        for r in new_resources:
            if o[0]['url'].split('/')[:-1] == r[0]['url'].split('/')[:-1] and not date_collision_present(o, r):
                r += o
                placed = True
                break

        if placed == False:
            new_resources.append(o)
    resources = new_resources

    ## C5 - line up those with equal subdomains
    new_resources = []
    for o in resources:
        placed = False
        for r in new_resources:
            if urlparse(o[0]['url']).netloc == urlparse(r[0]['url']).netloc and not date_collision_present(o, r):
                r += o
                placed = True
                break

        if placed == False:
            new_resources.append(o)
    resources = new_resources

    FIRST_T = 1428799569220
    # reduce to expected JSON format
    final_resources = []
    for ind, resource in enumerate(resources):
        for view in resource: 
            view['date'] = int((view['date'] - FIRST_T) / (24 * 60 * 60 * 1000))
        
        view_list = []
        for view in resource:
            try:
                i = list(map(itemgetter('date'), view_list)).index(view['date'])
                view_list[i]['n'] += 1
                view_list[i]['details'].append("{0} - {1}".format(view['url'], view['hash']))
            except ValueError:
                view_list.append({'date': view['date'], 'n': 1, 'details': ["{0} - {1}".format(view['url'], view['hash'])]})

        final_resources.append({'name': "Resource #{0}".format(ind),
                                'views': view_list,
                                'total': len(resource)})

    return render_template('visualizations/aligned_scripts.html',
                           json_data=json.dumps(final_resources))


@app.route('/')
def index():
    return app.send_static_file("index.html")


@app.route('/search/')
def search():
    """ 
    this is a temporary hack to let us serve query links that end in ?query=XXX off of
    a path that's been added to the robots.txt file to prevent google from indexing them
    """
    return app.send_static_file("index.html")



