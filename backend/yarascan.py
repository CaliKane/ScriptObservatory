#!/usr/bin/python3
#

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from requests import get
from html import escape
from os import environ
from random import randint
from smtplib import SMTP
from subprocess import check_output, CalledProcessError
from sys import argv
from time import sleep, time


MAX_HASHES = 500
MAX_PAGES_PER_HASH = 25
YARA_SCAN_TIMEOUT = 1500

SCRIPT_QUERY_URL  = "https://scriptobservatory.org/api/search?script_by_hash={0}"  

SUCCESS_SUBJECT = "YARA Scan Results (success!)"
SUCCESS_MESSAGE = "<html><head></head><body><u>Query:</u><br>{0}<br><br><u>Warning:</u><br>{1}</u><br><br><u>Hits:</u><br>{2}<u>Elapsed Time:</u><br>{3} seconds</body></html>"

FAILURE_SUBJECT = "YARA Scan Results (error!)"
FAILURE_MESSAGE = "<html><head></head><body>Query:<br>{0}<br><br>Error:<br>{1}<br><br>Check your YARA syntax!</body></html>"

WARNING_MESSAGE = """A maximum of {0} hashes and {1} webpages for each hash will be shown here. 
                  To see full results, refine your YARA rule or query the server directly.""".format(MAX_HASHES, MAX_PAGES_PER_HASH)

try:
    EMAIL_WHITELIST = environ['EMAIL_WHITELIST'].split(',')
except KeyError as e:
    EMAIL_WHITELIST = []


def sendmail(dest_addr, subject, message):
    """ send an email with subject/content *subject*/*message* to *dest_addr* using
        the credentials specified with env variables GMAIL_ACCOUNT & GMAIL_PASSWORD. """
    src_addr = environ["GMAIL_ACCOUNT"]

    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = src_addr
    msg['To'] = dest_addr
    
    html = MIMEText(message, 'html')
    msg.attach(html)

    with SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(src_addr, environ["GMAIL_PASSWORD"])
        smtp.sendmail(src_addr, dest_addr, msg.as_string())


def drop_rule_file(text):
    """ creates temp file with contents *text* and returns its absolute path """
    filepath = "/tmp/{0}.yara".format(randint(0,9999))
    with open(filepath, 'w') as f:
        f.write(text)
    return filepath


def run_yara_scan(dst_email, rule):
    search_directory = "/home/andy/projects/ScriptObservatory/backend/static/script-content/"  # move to env var

    if dst_email not in EMAIL_WHITELIST: 
        print("{0} not in email whitelist!".format(dst_email))
        sendmail(environ["GMAIL_ACCOUNT"], "Rejected YARA Scan", "{0} is not in the whitelist!".format(dst_email))
        exit(1)

    tmp_file = drop_rule_file(rule)
    
    try:
        start_t = time()
        output = check_output("nice -n 8 yara --threads=1 {0} {1}".format(tmp_file, search_directory), shell=True, timeout=YARA_SCAN_TIMEOUT)
        end_t = time()

        output = output.decode("utf-8")
        output = output.replace("{0}/".format(search_directory), "")
        output = output.replace(".txt", "")
        output = output.split('\n')

        if len(output) == 0:
            final_output = "no results found"
        
        else:
            if len(output) > MAX_HASHES:
                output = output[:MAX_HASHES]

            final_output = ""
            for match in output:
                if match == '': continue
                sleep(0.1)
                h = match[-64:]  # the hash is the last 64 characters of *match*
                
                r = get(SCRIPT_QUERY_URL.format(h), verify=False)
                assert r.status_code == 200
                
                results = r.json()['objects']
                if len(results) > MAX_PAGES_PER_HASH: 
                    results = results[:MAX_PAGES_PER_HASH] 
                results = ['<a href="https://scriptobservatory.org/search/?query={0}" target="_blank">{0}</a>, '.format(r) for r in results]
                if len(results) == 0:
                    results = ['(no webpages found)']

                final_output += "Hash {0} matches, seen on:<br>{1}<br><br>".format('<a href="https://scriptobservatory.org/script-content/{0}" target="_blank">{0}</a>'.format(h), 
                                                                                   ' '.join(results))
        
        subject = SUCCESS_SUBJECT
        message = SUCCESS_MESSAGE.format(escape(rule).replace('\n', '<br>'), 
                                         WARNING_MESSAGE, 
                                         final_output,
                                         end_t-start_t)

    except CalledProcessError as e:
        output = str(e)
        subject = FAILURE_SUBJECT
        message = FAILURE_MESSAGE.format(escape(rule).replace('\n', '<br>'),
                                         output)

    sendmail(dst_email, subject, message)
    

if __name__ == "__main__":
    dst_email = argv[1]
    rule = argv[2]
    run_yara_scan(dst_email, rule)

    
