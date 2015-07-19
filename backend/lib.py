from backend import app
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from smtplib import SMTP


def sendmail(dest_addr, subject, message):
    """ send an email with subject/content *subject*/*message* to *dest_addr*
        using the credentials specified with config options SMTP_ACCOUNT &
        SMTP_PASSWORD. """
    src_addr = app.config["MAIL_FROM"]

    msg = MIMEMultipart('alternative')
    msg['Subject'] = "{0}{1}".format(app.config['MAIL_PREFIX'], subject)
    msg['From'] = src_addr
    msg['To'] = dest_addr

    html = MIMEText(message, 'html')
    msg.attach(html)

    with SMTP(app.config['SMTP_SERVER'], app.config['SMTP_PORT']) as smtp:
        smtp.starttls()
        smtp.login(src_addr, app.config["SMTP_PASSWORD"])
        smtp.sendmail(src_addr, dest_addr, msg.as_string())
