import hashlib
import json
import jwt
import logging
import math
import secrets
import re
import requests
import urllib.parse
from typing import Optional
from datetime import datetime, timedelta
from functools import wraps

from flask import redirect, request, session, flash, make_response, current_app as app
from flask_mail import Message
from werkzeug.security import check_password_hash

from db import db


USER_PERM = {
    "SUPERADMIN": 0,
    "ADMIN": 1,
    "PROBLEM_MANAGER": 2,
    "CONTENT_MANAGER": 3,
}

PROBLEM_STAT = {
    "PUBLISHED": 0,
    "DRAFT": 1,
    "ARCHIVED": 2,
}


def sha256sum(string):
    return hashlib.sha256(string.encode("utf-8")).hexdigest()


def check_perm(required_perms: list, user_perms: Optional[set] = None) -> bool:
    """
    Check if the user has sufficient permissions to perform an action
    Alternatively, check if user_perms matches any of the required_perms
    """
    required_perms = set([USER_PERM[x] for x in required_perms])
    if user_perms is None:
        if session.get("perms"):
            user_perms = session["perms"]
        else:
            user_perms = set()
    return bool(user_perms.intersection(required_perms))


def json_fail(message: str, http_code: int):
    """
    Return the fail message as a JSON response with the specified http code
    """
    resp = make_response((json.dumps({"status": "fail", "message": message}), http_code))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def json_success(data: dict) -> str:
    """
    Return the requested information with status: success
    """
    resp = make_response(json.dumps({"status": "success", "data": data}))
    resp.headers['Content-Type'] = 'application/json; charset=utf-8'
    return resp


def api_logged_in() -> bool:
    """
    Check whether the user is logged in, using API key or session
    """
    # Check session
    if session and "user_id" in session and session["user_id"] > 0:
        return True

    # Get API key
    key = None
    if request.method == "GET" and "key" in request.args:
        key = request.args["key"]
    elif request.method == "POST" and "key" in request.form:
        key = request.form["key"]
    if key is None:
        return False

    # Check API key
    user = db.execute("SELECT * FROM users WHERE api=?", sha256sum(request.args["key"]))
    return len(user) == 1


def api_login_required(f):
    """
    Decorate API routes to require login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if api_logged_in():
            return f(*args, **kwargs)
        else:
            return json_fail("Unauthorized", 401)
    return decorated_function


def api_get_perms() -> set:
    """
    Get the permissions of the session or API key holder
    """
    if session and "perms" in session:
        return session["perms"]

    # Get API key
    key = None
    if request.method == "GET" and "key" in request.args:
        key = request.args["key"]
    elif request.method == "POST" and "key" in request.form:
        key = request.form["key"]
    if key is None:
        return set()

    # Check API key
    user = db.execute("SELECT * FROM users WHERE api=?", sha256sum(request.args["key"]))
    if len(user) == 0:
        return set()
    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user[0]["id"])
    return set([x["perm_id"] for x in perms])


def api_admin() -> bool:
    """
    Check whether the user is an admin, using API key or session
    """
    return check_perm(["ADMIN", "SUPERADMIN"], api_get_perms())


def api_perm(perms) -> bool:
    """
    Check whether the API user matches any given permission, using API key or session
    """
    return check_perm(perms, api_get_perms())


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + urllib.parse.quote(request.full_path))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """
    Decorate routes to require admin login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login?next=" + urllib.parse.quote(request.full_path))
        if not check_perm(["ADMIN", "SUPERADMIN"]):
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function


def perm_required(perms):
    """
    Decorate routes to require admin login.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get("user_id") is None:
                return redirect("/login?next=" + urllib.parse.quote(request.full_path))
            if not check_perm(perms):
                return redirect("/")
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def generate_password():
    """
    Generates a random 16-character password.

    used on Users page to manually reset passwords.
    """
    password = secrets.token_urlsafe(16)
    return password


def send_email(subject, sender, recipients, text, bcc=None):
    from application import mail
    message = Message(subject, sender=sender, recipients=recipients, html=text, bcc=bcc)
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


def verify_flag(flag):
    """
    Check if flag contains only up to 1024 printable ASCII characters
    """
    return bool(re.match(r'^[ -~]{0,1024}$', flag))


def check_captcha(secret, response, sitekey):
    """
    Verify the site captcha
    """
    if not response:  # No captcha, possibly if the request is made by a naive script
        flash('CAPTCHA invalid', 'danger')
        return False
    captcha = requests.post('https://hcaptcha.com/siteverify', data={
        'secret': secret,
        'response': response,
        'sitekey': sitekey
    })
    if not captcha.json()['success']:
        flash('CAPTCHA invalid', 'danger')
        return False
    return True


def create_jwt(data, secret_key, time=1800):
    """
    Creates a JWT token containing data and encrypted using secret_key
    """
    data['expiration'] = (datetime.utcnow() + timedelta(seconds=time)).isoformat()
    return jwt.encode(data, secret_key, algorithm='HS256')


def update_dyn_score(contest_id, problem_id, update_curr_user=True, d_solves=1):
    """
    Updates the dynamic scoring of contest_id/problem_id, using the db object.
    A transaction must be started before calling this function.
    For details see: https://www.desmos.com/calculator/eifeir81wk
                     https://github.com/jdabtieu/CTFOJ/issues/2
    """
    if update_curr_user:
        db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                    "VALUES(:cid, :uid, :pid)"),
                   cid=contest_id, pid=problem_id, uid=session["user_id"])
    check = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                        "problem_id=:pid"), cid=contest_id, pid=problem_id)
    solves = db.execute(
        ("SELECT COUNT(user_id) AS cnt FROM contest_solved WHERE contest_id=? AND "
         "problem_id=? AND user_id NOT IN (SELECT user_id FROM contest_users WHERE "
         "contest_id=? AND hidden != 0)"),
        contest_id, problem_id, contest_id)[0]["cnt"]
    N_min = check[0]["score_min"]
    N_max = check[0]["score_max"]
    N_users = check[0]["score_users"]
    d = 11 * math.log(N_max - N_min) + N_users
    old_points = min(math.ceil(math.e**((d - (solves - d_solves)) / 11) + N_min), N_max)
    new_points = min(math.ceil(math.e**((d - solves) / 11) + N_min), N_max)
    point_diff = new_points - old_points

    # Set new point value of problem
    db.execute(("UPDATE contest_problems SET point_value=:pv WHERE "
                "contest_id=:cid AND problem_id=:pid"),
               pv=new_points, cid=contest_id, pid=problem_id)

    if update_curr_user:
        db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
                    "points=points+:points WHERE contest_id=:cid AND user_id=:uid"),
                   cid=contest_id, points=old_points, uid=session["user_id"])

    # Update points of all users who previously solved the problem
    db.execute(("UPDATE contest_users SET points=points+:point_change "
                "WHERE contest_id=:cid AND user_id IN "
                "(SELECT user_id FROM contest_solved WHERE "
                "contest_id=:cid AND problem_id=:pid)"),
               point_change=point_diff, cid=contest_id, pid=problem_id)


def login_chk(rows):
    """
    Determines if the user is allowed to login
    Used by login() in application.py
    rows is a result of a db query for the user
    """
    logger = logging.getLogger("CTFOJ")
    # Check if username and password match db entry
    if len(rows) != 1 or not check_password_hash(rows[0]["password"],
                                                 request.form.get("password")):
        flash('Incorrect username/password', 'danger')
        logger.info(f"Incorrect login attempt from IP {request.remote_addr}",
                    extra={"section": "auth"})
        return 401

    # Check if user is banned
    if rows[0]["banned"]:
        flash('You are banned! Please message an admin to appeal the ban', 'danger')
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) tried to login "
                     "but is banned"), extra={"section": "auth"})
        return 403

    # Check if user's account is confirmed
    if not rows[0]["verified"]:
        flash('You have not confirmed your account yet. Please check your email', 'danger')  # noqa
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) tried to login "
                     "but has not comfirmed their account"), extra={"section": "auth"})
        return 403

    return 0


def register_chk(username, password, email):
    """
    Determines if the user is allowed to register
    Used by register() in application.py
    """
    if not username or not verify_text(username):
        flash('Invalid username', 'danger')
        return 400

    if not password or len(password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return 400

    if "+" in email:
        flash('Plus character not allowed in email', 'danger')
        return 400

    return 0


def parse_datetime(s):
    """
    Parses a datetime stored in the database into a Python datetime object
    """
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")


def contest_ended(info):
    """
    Determine if the contest from db query info has ended
    Returns whether the contest is over or not
    """
    end = parse_datetime(info["end"])
    return datetime.utcnow() > end


def rejudge_contest_problem(contest_id, problem_id, new_flag):
    """
    Rejudges a contest problem
    """
    db.execute("BEGIN")
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=? AND problem_id=?",
        contest_id, problem_id)[0]

    # Reset all previously correct submissions
    affected_users = [x["user_id"] for x in db.execute(
        "SELECT user_id FROM contest_solved WHERE contest_id=? AND problem_id=?",
        contest_id, problem_id
    )]
    db.execute("UPDATE contest_users SET points=points-? WHERE user_id IN (?)",
               data["point_value"], affected_users)
    db.execute(
        "UPDATE submissions SET correct=0 WHERE contest_id=? AND problem_id=?",
        contest_id, problem_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=? AND problem_id=?",
               contest_id, problem_id)
    if data["score_users"] >= 0:  # Reset dynamic scoring
        update_dyn_score(contest_id, problem_id, False)

    # Set all new correct submissions
    db.execute(("UPDATE submissions SET correct=1 WHERE contest_id=? AND "
                "problem_id=? AND submitted=?"),
               contest_id, problem_id, new_flag)
    affected_users += [x["user_id"] for x in db.execute(
        ("SELECT DISTINCT user_id FROM submissions WHERE contest_id=? AND "
         "problem_id=? AND correct=1"),
        contest_id, problem_id)]
    affected_users = list(set(affected_users))  # Remove duplicates
    db.execute(("INSERT INTO contest_solved (user_id, contest_id, problem_id) "
                "SELECT DISTINCT user_id, contest_id, problem_id FROM submissions WHERE "
                "contest_id=? AND problem_id=? AND correct=1"),
               contest_id, problem_id)
    if data["score_users"] == -1:  # Instructions for static scoring
        old_points = data["point_value"]
    else:  # Instructions for dynamic scoring
        old_points = data["score_max"]
        update_dyn_score(contest_id, problem_id, False)
    db.execute(("UPDATE contest_users SET points=points+? WHERE user_id IN (SELECT "
                "user_id FROM contest_solved WHERE contest_id=? AND problem_id=?)"),
               old_points, contest_id, problem_id)
    db.execute("UPDATE contest_users SET lastAC=NULL WHERE user_id IN (?)",
               affected_users)
    new_lastAC = db.execute(
        ("SELECT user_id, max(firstAC) AS lastAC FROM ("
         "SELECT user_id, min(date) AS firstAC, problem_id FROM submissions WHERE "
         "contest_id=? AND correct=1 GROUP BY user_id, problem_id ORDER BY user_id ASC) "
         "GROUP BY user_id"), contest_id)
    for entry in new_lastAC:
        # sqlite3 < 3.33 doesn't support UPDATE FROM
        db.execute("UPDATE contest_users SET lastAC=? WHERE user_id=?",
                   entry["lastAC"], entry["user_id"])
    db.execute("COMMIT")


def check_submit_rate_limit(contest_id, problem_id):
    """
    Checks if the user has submitted too many times in the past minute/hour
    """
    rl_min = app.config.get("SUBMIT_RATE_LIMIT_MIN")
    rl_hour = app.config.get("SUBMIT_RATE_LIMIT_HOUR")

    if rl_min:  # Do not rate limit if rl_min is zero or undefined
        past_min = db.execute(("SELECT COUNT(*) AS cnt FROM submissions WHERE "
                               "contest_id=? AND problem_id=? AND user_id=? AND "
                               "date > datetime('now', '-1 minute')"),
                              contest_id, problem_id, session["user_id"])[0]["cnt"]
        if past_min >= rl_min:
            return (f"You are submitting too fast! You may only submit {rl_min} time(s) "
                    "per minute. Please wait a while before submitting again.")
    if rl_hour:  # Do not rate limit if rl_min is zero or undefined
        past_hour = db.execute(("SELECT COUNT(*) AS cnt FROM submissions WHERE "
                                "contest_id=? AND problem_id=? AND user_id=? AND "
                                "date > datetime('now', '-1 hour')"),
                               contest_id, problem_id, session["user_id"])[0]["cnt"]
        if past_hour >= rl_hour:
            return (f"You are submitting too fast! You may only submit {rl_hour} time(s) "
                    "per hour. Please wait a while before submitting again.")
    return None
