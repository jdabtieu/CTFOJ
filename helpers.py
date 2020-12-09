import secrets
from functools import wraps

from flask import redirect, request, session
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
    password = secrets.token_urlsafe(16)
    return password


def send_email(subject, sender, recipients, text, mail):
    message = Message(subject, sender=sender, recipients=recipients, body=text)
    mail.send(message)

def read_file(filename):
    file = open(filename, 'r')
    contents = file.read()
    file.close()
    return contents
