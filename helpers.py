import os
import secrets
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps

import jwt
import requests
from flask import redirect, render_template, request, session
from flask_mail import Mail, Message


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


def contest_retrieve(session, request, db, contestid):
    solve_info = db.execute(
        "SELECT * FROM :cid WHERE user_id=:id", cid=contestid, id=session["user_id"])

    if len(solve_info) == 0:
        db.execute("INSERT INTO :cid (user_id) VALUES(:id)",
                   cid=contestid, id=session["user_id"])
        solve_info = db.execute("SELECT * FROM :cid WHERE user_id=:id",
                                cid=contestid, id=session["user_id"])[0]
    else:
        solve_info = solve_info[0]

    data = []

    info = db.execute("SELECT * FROM :cidinfo WHERE draft=0 ORDER BY category ASC, id ASC",
                      cidinfo=contestid + "info")
    for row in info:
        keys = {
            "name": row["name"],
            "category": row["category"],
            "id": row["id"],
            "solved": solve_info[row["id"]],
            "point_value": row["point_value"]
        }
        data.insert(len(data), keys)
    return data


def generate_password():
    password = secrets.token_urlsafe(16)
    return password


def send_email(subject, sender, recipients, text, mail):
    message = Message(subject, sender=sender, recipients=recipients, body=text)
    mail.send(message)
