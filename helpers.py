import secrets
import re
import requests
from functools import wraps

from flask import redirect, request, session, flash
from flask_mail import Message


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + request.path)
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorate routes to require admin login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + request.path)
        if not session.get("admin"):
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


def generate_password():
    """
    Generates a random 16-character password.

    used on Users page to manually reset passwords.
    """
    password = secrets.token_urlsafe(16)
    return password


def send_email(subject, sender, recipients, text, mail, bcc=None):
    message = Message(subject, sender=sender, recipients=recipients, body=text, bcc=bcc)
    mail.send(message)


def read_file(filename):
    with open(filename, 'r') as file:
        return file.read()


def write_file(filename, text):
    with open(filename, 'w') as file:
        file.write(text)
    return


def verify_text(text):
    """
    Check if text only contains A-Z, a-z, 0-9, underscores, and dashes
    """
    return bool(re.match(r'^[\w\-]+$', text))


def check_captcha(secret, response, sitekey):
    """
    Verify the site captcha
    """
    captcha = requests.post('https://hcaptcha.com/siteverify', data={
        'secret': secret,
        'response': response,
        'sitekey': sitekey
    })
    if not captcha.json()['success']:
        return False
    return True


def check_version():
    """
    Checks if CTFOJ is up to date with the latest version on GitHub
    """
    curr_version = "v1.5.0"
    try:
        latest_version = requests.get(
            "https://api.github.com/repos/jdabtieu/CTFOJ/releases/latest").json()["name"]
        if curr_version != latest_version:
            flash(("You are not up-to-date! Please notify the site administrator. "
                  f"Current version: {curr_version}, Latest version: {latest_version}"),
                  "danger")
    except Exception:
        flash(("Latest version could not be detected. Please make sure "
               "https://api.github.com isn't blocked by a firewall."), "warning")
    return
