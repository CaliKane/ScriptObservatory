#!/usr/bin/python3
#

from os import environ
from smtplib import SMTP



def sendmail(dest_addr, message):
    src_addr = environ["GMAIL_ACCOUNT"]
    
    with SMTP("smtp.gmail.com", 587) as smtp:
        smtp.starttls()
        smtp.login(src_addr, environ["GMAIL_PASSWORD"])
        smtp.sendmail(src_addr, dest_addr, message)

message = "test message"
sendmail("andy@andymartin.cc", message)

