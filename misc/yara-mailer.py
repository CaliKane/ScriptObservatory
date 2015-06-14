#!/usr/bin/python3
#

from os import environ
from random import randint
from smtplib import SMTP
from subprocess import check_output, CalledProcessError
from sys import argv


TIMEOUT = 1200
WHITELIST = ["andy@andymartin.cc"]


def sendmail(dest_addr, message):
    """ send an email with content *message* to *dest_addr* using the external SMTP server
        specified with environment variables GMAIL_ACCOUNT / GMAIL_PASSWORD. """
    src_addr = environ["GMAIL_ACCOUNT"]
    
    with SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(src_addr, environ["GMAIL_PASSWORD"])
        smtp.sendmail(src_addr, dest_addr, message)


def drop_rule_file(text):
    """ creates temp file with contents *text* and returns absolute path """
    filepath = "/tmp/{0}.yara".format(randint(0,9999))
    with open(filepath, 'w') as f:
        f.write(text)
    return filepath


if __name__ == "__main__":
    dst_email = argv[1]
    rule = argv[2]
    search_directory = "/home/andy/projects/ScriptObservatory/backend/static/script-content/"  # move to env var
    
    if dst_email not in WHITELIST: 
        print("{0} not in email whitelist!".format(dst_email))
        exit(1)

    tmp_file = drop_rule_file(rule)
    try:
        output = check_output("yara --threads=1 {0} {1}".format(tmp_file, search_directory), shell=True, timeout=TIMEOUT)
        output = output.decode("utf-8")
        output = output.replace("{0}/".format(search_directory), "")
        output = output.replace(".txt", "")

        if len(output) == 0:
            output = "no results found."
        elif len(output.split('\n')) > 10000:
            output = "too many results. (>10,000)"

        message = "Subject: YARA Scan Results (success!)\n\nQuery:\n {0}\n\nHits (sha256):\n{1}".format(rule, output)

    except CalledProcessError as e:
        print(e)
        output = str(e)
        message = "Subject: YARA Scan Results (error!)\n\nQuery:\n {0}\n\nError:\n{1}\n\nCheck your YARA syntax!".format(rule, output)

    sendmail(dst_email, message)
    
    if dst_email != environ["GMAIL_ACCOUNT"]:
        sendmail(environ["GMAIL_ACCOUNT"], message)

