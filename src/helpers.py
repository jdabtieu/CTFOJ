import json
import jwt
import logging
import math
import secrets
import re
import requests
from datetime import datetime, timedelta
from functools import wraps

from flask import redirect, request, session, flash, Markup, make_response
from flask_mail import Message
from werkzeug.security import check_password_hash


def json_fail(message: str, http_code: int):
    """
    Return the fail message as a JSON response with the specified http code
    """
    return make_response((json.dumps({"status": "fail", "message": message}), http_code))


def json_success(data: dict) -> str:
    """
    Return the requested information with status: success
    """
    return json.dumps({"status": "success", "data": data})


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
    if request.method == "POST" and "key" in request.form:
        key = request.form["key"]
    if key is None:
        return False

    # Check API key
    from application import db
    user = db.execute("SELECT * FROM users WHERE api=?", request.args["key"])
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


def api_admin() -> bool:
    """
    Check whether the user is an admin, using API key or session
    """
    # Check session
    if session and "admin" in session and session["admin"] == 1:
        return True

    # Get API key
    key = None
    if request.method == "GET" and "key" in request.args:
        key = request.args["key"]
    if request.method == "POST" and "key" in request.form:
        key = request.form["key"]
    if key is None:
        return False

    # Check API key
    from application import db
    user = db.execute("SELECT * FROM users WHERE api=? AND admin=1", request.args["key"])
    return len(user) == 1


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
    captcha = requests.post('https://hcaptcha.com/siteverify', data={
        'secret': secret,
        'response': response,
        'sitekey': sitekey
    })
    if not captcha.json()['success']:
        flash('CAPTCHA invalid', 'danger')
        return False
    return True


def check_version():
    """
    Checks if CTFOJ is up to date with the latest version on GitHub
    """
    curr_version = "v3.1.0"
    try:
        latest_version = requests.get(
            "https://api.github.com/repos/jdabtieu/CTFOJ/releases/latest").json()["name"]
        if curr_version != latest_version:
            message = Markup((
                "You are not up-to-date! Please notify the site administrator. "
                f"Current version: {curr_version}, Latest version: {latest_version}. "
                 "Upgrade <a href=\"https://github.com/jdabtieu/CTFOJ/releases\">here</a>."))  # noqa
            flash(message, "danger")

    except Exception:
        flash(("Latest version could not be detected. Please make sure "
               "https://api.github.com isn't blocked by a firewall."), "warning")
    return


def create_jwt(data, secret_key, time=1800):
    """
    Creates a JWT token containing data and encrypted using secret_key
    """
    data['expiration'] = (datetime.utcnow() + timedelta(seconds=time)).isoformat()
    return jwt.encode(data, secret_key, algorithm='HS256')


def update_dyn_score(contest_id, problem_id, update_curr_user=True):
    from application import db
    """
    Updates the dynamic scoring of contest_id/problem_id, using the db object
    For details see: https://www.desmos.com/calculator/eifeir81wk
                     https://github.com/jdabtieu/CTFOJ/issues/2
    Prereqs for using this function: user solve entry must already be in contest_solved
    """
    db.execute("BEGIN")
    check = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                        "problem_id=:pid"), cid=contest_id, pid=problem_id)
    solves = len(db.execute(
        "SELECT user_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id))
    N_min = check[0]["score_min"]
    N_max = check[0]["score_max"]
    N_users = check[0]["score_users"]
    d = 11 * math.log(N_max - N_min) + N_users
    old_points = min(math.ceil(math.e**((d - solves + 1) / 11) + N_min), N_max)
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
    db.execute("COMMIT")


def contest_exists(contest_id):
    from application import db
    """
    Checks if the contest with contest_id exists
    """
    return len(db.execute("SELECT * FROM contests WHERE id=:id", id=contest_id)) == 1


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


def contest_ended(info):
    """
    Determine if the contest from db query info has ended
    Returns whether the contest is over or not
    info should be an array (len 1) of a dict representing the contest data from the db
    """
    end = datetime.strptime(info[0]["end"], "%Y-%m-%d %H:%M:%S")
    return datetime.utcnow() > end


def rejudge_contest_problem(contest_id, problem_id, new_flag):
    from application import db
    """
    Rejudges a contest problem
    """
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)[0]

    # Reset all previously correct submissions
    db.execute(("UPDATE contest_users SET points=points-:points WHERE user_id IN (SELECT "
                "user_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid)"),
               points=data["point_value"], cid=contest_id, pid=problem_id)
    db.execute(
        "UPDATE submissions SET correct=0 WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
               cid=contest_id, pid=problem_id)
    if data["score_users"] >= 0:  # Reset dynamic scoring
        update_dyn_score(contest_id, problem_id, update_curr_user=False)

    # Set all new correct submissions
    db.execute(("UPDATE submissions SET correct=1 WHERE contest_id=:cid AND "
                "problem_id=:pid AND submitted=:flag"),
               cid=contest_id, pid=problem_id, flag=new_flag)
    db.execute(("INSERT INTO contest_solved (user_id, contest_id, problem_id) "
                "SELECT DISTINCT user_id, contest_id, problem_id FROM submissions WHERE "
                "contest_id=:cid AND problem_id=:pid AND correct=1"),
               cid=contest_id, pid=problem_id)
    if data["score_users"] == -1:  # Instructions for static scoring
        old_points = data["point_value"]
    else:  # Instructions for dynamic scoring
        old_points = data["score_max"]
        update_dyn_score(contest_id, problem_id, update_curr_user=False)
    db.execute(("UPDATE contest_users SET points=points+:points WHERE user_id IN (SELECT "
                "user_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid)"),
               points=old_points, cid=contest_id, pid=problem_id)
