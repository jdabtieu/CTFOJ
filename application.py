import os
import sys
import logging
import shutil
from datetime import datetime, timedelta
from tempfile import mkdtemp

import jwt
from cs50 import SQL
from flask import (Flask, flash, redirect, render_template, request,
                   send_from_directory, session)
from flask_mail import Mail
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException, InternalServerError, default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *

app = Flask(__name__)
maintenance_mode = False
try:
    app.config.from_object('settings')
except Exception as e:
    sys.stderr.write(str(e))
    app.config.from_object('default_settings')
app.config['SESSION_FILE_DIR'] = mkdtemp()
app.jinja_env.globals['CLUB_NAME'] = app.config['CLUB_NAME']
app.jinja_env.globals['USE_CAPTCHA'] = app.config['USE_CAPTCHA']

# Configure logging
try:
    logging.basicConfig(
        filename=app.config['LOGGING_FILE_LOCATION'],
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
    )
    logging.getLogger().addHandler(logging.StreamHandler())
except Exception as e:  # when testing
    sys.stderr.write(str(e))
    os.mkdir('logs')
    logging.basicConfig(
        filename='logs/application.log',
        level=logging.DEBUG,
        format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s'
    )
    logging.getLogger().addHandler(logging.StreamHandler())

# Configure flask-session
Session(app)

# Configure cs50
try:
    db = SQL("sqlite:///database.db")
except Exception as e:  # when testing
    sys.stderr.write(str(e))
    open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")

# Configure flask-mail
mail = Mail(app)

# Configure flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)


@app.before_request
def check_for_maintenance():
    # crappy if/elses used here for future expandability
    global maintenance_mode
    # don't block the user if they only have the csrf token
    if maintenance_mode and request.path != '/login':
        if not session:
            return render_template("error/maintenance.html"), 503
        elif not session['admin']:
            return render_template("error/maintenance.html"), 503


@app.route("/")
@login_required
def index():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 10

    data = db.execute(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM announcements"))

    for i in range(len(data)):
        aid = data[i]["id"]

        data[i]["description"] = read_file(
            'metadata/announcements/' + str(aid) + '.md')

    return render_template("index.html", data=data, length=-(-length // 10))


@app.route("/assets/<path:filename>")
def get_asset(filename):
    return send_from_directory("assets/", filename)


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/dl/<path:filename>")
@login_required
def dl(filename):
    return send_from_directory("dl/", filename, as_attachment=True)


@csrf.exempt
@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget user id
    session.clear()

    if request.method == "GET":
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    # Ensure username and password were submitted
    if not request.form.get("username") or not request.form.get("password"):
        flash('Username and password cannot be blank', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'], request.form.get('h-captcha-response'), app.config['HCAPTCHA_SITE']):
            flash('CAPTCHA invalid', 'danger')
            return render_template("login.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
        flash('Incorrect username/password', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 401

    # Ensure user is not banned
    if rows[0]["banned"]:
        flash('You are banned! Please message an admin to appeal the ban', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 403

    # Ensure user has confirmed account
    if not rows[0]["verified"]:
        flash('You have not confirmed your account yet. Please check your email', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 403

    # implement 2fa verification via email
    if rows[0]["twofa"]:
        exp = datetime.utcnow() + timedelta(seconds=1800)
        email = rows[0]["email"]
        token = jwt.encode(
            {
                'email': email,
                'expiration': exp.isoformat()
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        ).decode('utf-8')
        text = render_template('email/confirm_login_text.txt',
                               username=request.form.get('username'), token=token)

        if not app.config['TESTING']:
            send_email('Confirm Your CTF Login',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

        flash('A login confirmation email has been sent to the email address you provided. Be sure to check your spam folder!', 'success')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE'])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["admin"] = rows[0]["admin"]

    # Redirect user to next page
    if request.form.get("next"):
        return redirect(request.form.get("next"))
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@csrf.exempt
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    # Ensure username is valid
    if not request.form.get("username"):
        flash('Username cannot be blank', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 400
    if not verify_text(request.form.get("username")):
        flash('Invalid username', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure password is not blank
    if not request.form.get("password") or len(request.form.get("password")) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 400
    if not request.form.get("confirmation") or request.form.get("password") != request.form.get("confirmation"):
        flash('Passwords do not match', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'], request.form.get('h-captcha-response'), app.config['HCAPTCHA_SITE']):
            flash('CAPTCHA invalid', 'danger')
            return render_template("register.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure username and email do not already exist
    rows = db.execute("SELECT * FROM users WHERE username = :username",
                      username=request.form.get("username"))
    if len(rows) > 0:
        flash('Username already exists', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 409
    rows = db.execute("SELECT * FROM users WHERE email = :email",
                      email=request.form.get("email"))
    if len(rows) > 0:
        flash('Email already exists', 'danger')
        return render_template("register.html", site_key=app.config['HCAPTCHA_SITE']), 409

    exp = datetime.utcnow() + timedelta(seconds=1800)
    email = request.form.get('email')
    token = jwt.encode(
        {
            'email': email,
            'expiration': exp.isoformat()
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    ).decode('utf-8')
    text = render_template('email/confirm_account_text.txt',
                           username=request.form.get('username'), token=token)

    db.execute("INSERT INTO users(username, password, email, join_date) VALUES(:username, :password, :email, datetime('now'))",
               username=request.form.get("username"),
               password=generate_password_hash(request.form.get("password")),
               email=request.form.get("email"))
    if not app.config['TESTING']:
        send_email('Confirm Your CTF Account',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

    flash('An account creation confirmation email has been sent to the email address you provided. Be sure to check your spam folder!', 'success')
    return render_template("register.html", site_key=app.config['HCAPTCHA_SITE'])


@app.route('/confirmregister/<token>')
def confirm_register(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0
    if not token:
        flash("Email verification link invalid", "danger")
        return redirect("/register")
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        db.execute(
            "DELETE FROM users WHERE verified=0 and email=:email", email=token['email'])
        flash("Email verification link expired; Please re-register", "danger")
        return redirect("/register")

    db.execute("UPDATE users SET verified=1 WHERE email=:email", email=token['email'])

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email = :email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = False  # ensure no one can get admin right after registering

    return redirect("/problem/helloworld")


@app.route('/confirmlogin/<token>')
def confirm_login(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0

    if not token:
        flash('Invalid login verification link', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 400
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Login verification link expired; Please re-login', 'danger')
        return render_template("login.html", site_key=app.config['HCAPTCHA_SITE']), 401

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email = :email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = user["admin"]

    return redirect("/")


@login_required
@app.route("/settings")
def settings():
    return render_template("settings.html")


@app.route("/settings/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "GET":
        return render_template("changepassword.html")

    # Reached using POST

    # Ensure passwords were submitted and they match
    if not request.form.get("password"):
        flash('Password cannot be blank', 'danger')
        return render_template("changepassword.html"), 400
    if not request.form.get("newPassword") or len(request.form.get("newPassword")) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("changepassword.html"), 400
    if not request.form.get("confirmation") or request.form.get("newPassword") != request.form.get("confirmation"):
        flash('Passwords do not match', 'danger')
        return render_template("changepassword.html"), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE id = :id",
                      id=session["user_id"])
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], request.form.get("password")):
        flash('Incorrect password', 'danger')
        return render_template("changepassword.html"), 401

    db.execute("UPDATE users SET password = :new WHERE id = :id",
               new=generate_password_hash(request.form.get("newPassword")),
               id=session["user_id"])

    flash("Password change successful", "success")
    return redirect("/settings")


@login_required
@app.route("/settings/toggle2fa")
def toggle2fa():
    rows = db.execute("SELECT * FROM users WHERE id = :id",
                      id=session["user_id"])

    if rows[0]["twofa"]:
        db.execute("UPDATE users SET twofa = 0 WHERE id = :id", id=session["user_id"])
        flash("2FA successfully disabled", "success")
    else:
        db.execute("UPDATE users SET twofa = 1 WHERE id = :id", id=session["user_id"])
        flash("2FA successfully enabled", "success")
    return redirect("/settings")


@csrf.exempt
@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    session.clear()

    if request.method == "GET":
        return render_template("forgotpassword.html",
                               site_key=app.config['HCAPTCHA_SITE'])

    # Reached via POST

    email = request.form.get("email")
    if not email:
        flash('Email cannot be blank', 'danger')
        return render_template("forgotpassword.html"), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'], request.form.get('h-captcha-response'), app.config['HCAPTCHA_SITE']):
            flash('CAPTCHA invalid', 'danger')
            return render_template("forgotpassword.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    rows = db.execute("SELECT * FROM users WHERE email = :email",
                      email=request.form.get("email"))

    if len(rows) == 1:
        exp = datetime.utcnow() + timedelta(seconds=1800)
        token = jwt.encode(
            {
                'user_id': rows[0]["id"],
                'expiration': exp.isoformat()
            },
            app.config['SECRET_KEY'],
            algorithm='HS256'
        ).decode('utf-8')
        text = render_template('email/reset_password_text.txt',
                               username=rows[0]["username"], token=token)
        if not app.config['TESTING']:
            send_email('Reset Your CTF Password',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text, mail)

    flash('If there is an account associated with that email, a password reset email has been sent', 'success')
    return render_template("forgotpassword.html")


@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def reset_password_user(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = token['user_id']
    except Exception as e:
        sys.stderr.write(str(e))
        user_id = 0
    if not user_id or datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Password reset link expired/invalid', 'danger')
        return redirect('/forgotpassword')

    if request.method == "GET":
        return render_template('resetpassword.html')

    if not request.form.get("password") or len(request.form.get("password")) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("resetpassword.html"), 400
    if not request.form.get("confirmation") or request.form.get("password") != request.form.get("confirmation"):
        flash('Passwords do not match', 'danger')
        return render_template("resetpassword.html"), 400

    db.execute("UPDATE users SET password = :new WHERE id = :id",
               new=generate_password_hash(request.form.get("password")), id=user_id)

    flash('Your password has been successfully reset', 'success')
    return redirect("/login")


@app.route("/contests")
@login_required
def contests():
    past = db.execute(
        "SELECT * FROM contests WHERE end < datetime('now') ORDER BY end DESC")
    current = db.execute(
        "SELECT * FROM contests WHERE end > datetime('now') AND start <= datetime('now') ORDER BY end DESC")
    future = db.execute(
        "SELECT * FROM contests WHERE start > datetime('now') ORDER BY start DESC")
    for contest in past:
        cid = contest["id"]
        contest["description"] = read_file('metadata/contests/' + cid + '/description.md')
    for contest in current:
        cid = contest["id"]
        contest["description"] = read_file('metadata/contests/' + cid + '/description.md')
    for contest in future:
        cid = contest["id"]
        contest["description"] = read_file('metadata/contests/' + cid + '/description.md')
    return render_template("contest/contests.html",
                           past=past, current=current, future=future)


@app.route("/contest/<contest_id>")
@login_required
def contest(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest started or user is admin
    start = datetime.strptime(contest_info[0]["start"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() < start and not session["admin"]:
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    title = contest_info[0]["name"]

    # Check for scoreboard permission
    scoreboard = contest_info[0]["scoreboard_visible"] or session["admin"]

    user_info = db.execute("SELECT * FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
                           cid=contest_id, uid=session["user_id"])

    if len(user_info) == 0:
        db.execute("INSERT INTO contest_users (contest_id, user_id) VALUES(:cid, :uid)",
                   cid=contest_id, uid=session["user_id"])

    solved_info = db.execute("SELECT problem_id FROM contest_solved WHERE contest_id=:cid AND user_id=:uid",
                             cid=contest_id, uid=session["user_id"])

    solved_data = set()
    for row in solved_info:
        solved_data.add(row["problem_id"])

    data = []

    info = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND draft=0 ORDER BY problem_id ASC, category ASC",
                      cid=contest_id)
    for row in info:
        keys = {
            "name": row["name"],
            "category": row["category"],
            "problem_id": row["problem_id"],
            "solved": 1 if row["problem_id"] in solved_data else 0,
            "point_value": row["point_value"]
        }
        data.insert(len(data), keys)

    return render_template("contest/contest.html", title=title, scoreboard=scoreboard,
                           data=data)


@app.route("/contest/<contest_id>/notify", methods=['GET', 'POST'])
@admin_required
def contest_notify(contest_id):
    if request.method == "GET":
        return render_template('admin/contestnotify.html')

    subject = request.form.get("subject")
    if not subject:
        flash('Must provide subject', 'danger')
        return render_template('admin/contestnotify.html'), 400
    message = request.form.get("message")
    if not message:
        flash('Must provide message', 'danger')
        return render_template('admin/contestnotify.html'), 400

    data = db.execute("SELECT email FROM contest_users JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid",
                      cid=contest_id)
    emails = [participant["email"] for participant in data]
    if not app.config['TESTING']:
        send_email(subject, app.config['MAIL_DEFAULT_SENDER'], [], message, mail, emails)

    flash('Participants sucessfully notified', 'success')
    return redirect("/contest/" + contest_id)


@app.route("/contest/<contest_id>/drafts")
@admin_required
def contest_drafts(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    data = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND draft=1",
                      cid=contest_id)

    return render_template("contest/draft_problems.html",
                           title=contest_info[0]["name"], data=data)


@app.route("/contest/<contest_id>/problem/<problem_id>", methods=["GET", "POST"])
@login_required
def contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    check = db.execute("SELECT * FROM contests WHERE id=:id", id=contest_id)
    if len(check) != 1:
        return render_template("contest/contest_noexist.html"), 404

    check = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
                       cid=contest_id, pid=problem_id)
    if len(check) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    # check problem exists
    check1 = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid AND draft=0",
                        cid=contest_id, pid=problem_id)
    if len(check1) != 1 and session["admin"] != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    check[0]["description"] = read_file(
        'metadata/contests/' + contest_id + '/' + problem_id + '/description.md')
    check[0]["hints"] = read_file(
        'metadata/contests/' + contest_id + '/' + problem_id + '/hints.md')

    if request.method == "GET":
        return render_template("contest/contest_problem.html", data=check[0])

    # Reached via POST

    # Ensure contest hasn't ended
    end = db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)
    end = datetime.strptime(end[0]["end"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > end:
        flash('This contest has ended', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    flag = request.form.get("flag")
    if not flag:
        flash('Cannot submit an empty flag', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    # Check if flag is correct
    if flag != check[0]["flag"]:
        db.execute("INSERT INTO submissions(date, user_id, problem_id, contest_id, correct) VALUES(datetime('now'), :uid, :pid, :cid, 0)",
                   uid=session["user_id"], pid=problem_id, cid=contest_id)
        flash('Your flag is incorrect', 'danger')
        return render_template("contest/contest_problem.html", data=check[0])

    db.execute("INSERT INTO submissions(date, user_id, problem_id, contest_id, correct) VALUES(datetime('now'), :uid, :pid, :cid, 1)",
               uid=session["user_id"], pid=problem_id, cid=contest_id)

    # Check if user has already found this flag
    check1 = db.execute("SELECT * FROM contest_solved WHERE contest_id=:cid AND user_id=:uid AND problem_id=:pid",
                        cid=contest_id, uid=session["user_id"], pid=problem_id)

    # check if user is in the contest
    check2 = db.execute("SELECT * FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
                        cid=contest_id, uid=session["user_id"])
    if len(check2) == 0:
        db.execute("INSERT INTO contest_users(contest_id, user_id) VALUES (:cid, :uid)",
                   cid=contest_id, uid=session["user_id"])

    if len(check1) == 0:
        points = check[0]["point_value"]
        db.execute("INSERT INTO contest_solved(contest_id, user_id, problem_id) VALUES(:cid, :uid, :pid)",
                   cid=contest_id, pid=problem_id, uid=session["user_id"])
        db.execute("UPDATE contest_users SET lastAC=datetime('now'), points=points+:points WHERE contest_id=:cid AND user_id=:uid",
                   cid=contest_id, points=points, uid=session["user_id"])

    flash('Congratulations! You have solved this problem!', 'success')
    return render_template("contest/contest_problem.html", data=check[0])


@app.route("/contest/<contest_id>/problem/<problem_id>/publish", methods=["POST"])
@admin_required
def publish_contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    check = db.execute("SELECT * FROM contests WHERE id=:id", id=contest_id)
    if len(check) != 1:
        return render_template("contest/contest_noexist.html"), 404

    check = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
                       cid=contest_id, pid=problem_id)

    if len(check) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    db.execute("UPDATE contest_problems SET draft=0 WHERE problem_id=:pid AND contest_id=:cid",
               pid=problem_id, cid=contest_id)

    flash('Problem successfully published', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@app.route('/contest/<contest_id>/problem/<problem_id>/edit', methods=["GET", "POST"])
@admin_required
def edit_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    data = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(data) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
                      cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    data[0]["description"] = read_file(
        'metadata/contests/' + contest_id + '/' + problem_id + '/description.md')
    data[0]["hints"] = read_file(
        'metadata/contests/' + contest_id + '/' + problem_id + '/hints.md')

    if request.method == "GET":
        return render_template('problem/editproblem.html', data=data[0])

    # Reached via POST

    new_name = request.form.get("name")
    new_description = request.form.get("description")
    new_hint = request.form.get("hints")
    new_category = request.form.get("category")
    new_points = request.form.get("point_value")

    if not new_name or not new_description or not new_category or not new_points:
        flash('You have not entered all required fields', 'danger'), 400
        return render_template('problem/editproblem.html', data=data[0])

    new_description = new_description.replace('\r', '')
    if not new_hint:
        new_hint = ""

    old_points = data[0]["point_value"]
    if old_points != new_points:
        point_change = int(new_points) - old_points
        need_update = db.execute("SELECT user_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
                    cid=contest_id, pid=problem_id)
        need_update = [user["user_id"] for user in need_update]
        db.execute(f"UPDATE contest_users SET points = points + :point_change WHERE contest_id=:cid AND user_id IN ({','.join([str(user) for user in need_update])})",
                    point_change=point_change, cid=contest_id)

    db.execute("UPDATE contest_problems SET name=:name, category=:category, point_value=:pv WHERE contest_id=:cid AND problem_id=:pid",
               name=new_name, category=new_category, pv=new_points,
               cid=contest_id, pid=problem_id)

    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.md', new_description)  # noqa
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', new_hint)

    flash('Problem successfully edited', 'success')
    return redirect(request.path[:-5])


@app.route("/contest/<contest_id>/scoreboard")
@login_required
def contest_scoreboard(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure proper permissions
    if not contest_info[0]["scoreboard_visible"] and not session["admin"]:
        flash('You are not allowed to view the scoreboard!', 'danger')
        return redirect("/contest/" + contest_id)

    # Render page
    data = db.execute("SELECT user_id, points, lastAC, username FROM contest_users JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid ORDER BY points DESC, lastAC ASC",
                      cid=contest_id)
    return render_template("contest/contestscoreboard.html",
                           title=contest_info[0]["name"], data=data)


@app.route("/contest/<contest_id>/addproblem", methods=["GET", "POST"])
@admin_required
def contest_add_problem(contest_id):
    # Ensure contest exists
    contest_info = db.execute(
        "SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest hasn't ended
    end = datetime.strptime(contest_info[0]["end"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() > end:
        flash('This contest has already ended', 'danger')
        return redirect('/contest/' + contest_id)

    if request.method == "GET":
        return render_template("admin/createproblem.html")

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description = request.form.get("description")
    hints = request.form.get("hints")
    point_value = request.form.get("point_value")
    category = request.form.get("category")
    flag = request.form.get("flag")
    draft = 1 if request.form.get("draft") else 0

    if not problem_id or not name or not description or not point_value or not category or not flag:
        flash('You have not entered all required fields', 'danger'), 400
        return render_template("admin/createproblem.html"), 400

    # Check if problem ID is valid
    if not verify_text(request.form.get("id")):
        flash('Invalid problem ID', 'danger')
        return render_template("admin/createproblem.html"), 400

    description = description.replace('\r', '')

    # Ensure problem does not already exist
    problem_info = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND (problem_id=:pid OR name=:name)",
                              cid=contest_id, pid=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("admin/createproblem.html"), 409

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        if not os.path.exists("dl/" + contest_id):
            os.makedirs("dl/" + contest_id)
        filename = problem_id + ".zip"
        filepath = "dl/" + contest_id + "/"
        file.save(filepath + filename)
        description += '<br><a href="/' + filepath + filename + '">' + filename + '</a>'

    # Modify problems table
    db.execute("INSERT INTO contest_problems(contest_id, problem_id, name, point_value, category, flag, draft) VALUES(:cid, :pid, :name, :point_value, :category, :flag, :draft)",
               cid=contest_id, pid=problem_id, name=name, point_value=point_value,
               category=category, flag=flag, draft=draft)

    os.makedirs(f'metadata/contests/{contest_id}/{problem_id}')
    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.md', description)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', hints)

    # Go to contest page on success
    flash('Problem successfully created', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@app.route('/contest/<contest_id>/problem/<problem_id>/export', methods=["GET", "POST"])
@admin_required
def export_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    data1 = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(data1) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
                      cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        end = datetime.strptime(data1[0]["end"], "%Y-%m-%d %H:%M:%S")
        if datetime.utcnow() < end:
            flash("Are you sure? The contest hasn't ended yet", 'warning')
            return render_template('contest/exportproblem.html', data=data[0])

        return render_template('contest/exportproblem.html', data=data[0])

    # Reached via POST

    new_id = contest_id + "-" + problem_id  # this should be safe already

    check = db.execute("SELECT * FROM problems WHERE id=:id", id=new_id)
    if len(check) != 0:
        flash('This problem has already been exported', 'danger')
        return render_template('contest/exportproblem.html', data=data[0])

    new_name = data1[0]["name"] + " - " + data[0]["name"]

    # Insert into problems databases
    db.execute("BEGIN")
    db.execute("INSERT INTO problems(id, name, point_value, category, flag) VALUES(:id, :name, :pv, :cat, :flag)",
               id=new_id, name=new_name, pv=data[0]["point_value"],
               cat=data[0]["category"], flag=data[0]["flag"])

    solved = db.execute("SELECT user_id, problem_id FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
                        cid=contest_id, pid=problem_id)
    for row in solved:
        db.execute("INSERT INTO problem_solved(user_id, problem_id) VALUES(:uid, :pid)",
                   uid=row['user_id'], pid=row['problem_id'])

    db.execute("COMMIT")

    os.makedirs('metadata/problems/' + new_id)
    shutil.copy('metadata/contests/' + contest_id + '/' + problem_id + '/description.md',
                'metadata/problems/' + new_id + '/description.md')
    shutil.copy('metadata/contests/' + contest_id + '/' + problem_id + '/hints.md',
                'metadata/problems/' + new_id + '/hints.md')
    open('metadata/problems/' + new_id + '/editorial.md', 'w').close()

    flash('Problem successfully exported', 'success')
    return redirect("/problem/" + new_id)


@app.route('/problems')
@login_required
def problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    solved_data = db.execute("SELECT problem_id FROM problem_solved WHERE user_id=:uid",
                             uid=session["user_id"])
    solved = set()
    for row in solved_data:
        solved.add(row["problem_id"])

    data = db.execute(
        "SELECT * FROM problems WHERE draft=0 ORDER BY id ASC LIMIT 50 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM problems WHERE draft=0"))

    return render_template('problem/problems.html',
                           data=data, solved=solved, length=-(-length // 50))


@app.route('/problems/draft')
@admin_required
def draft_problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    data = db.execute("SELECT * FROM problems WHERE draft=1 LIMIT 50 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM problems WHERE draft=1"))

    return render_template('problem/draft_problems.html',
                           data=data, length=-(-length // 50))


@app.route('/problem/<problem_id>', methods=["GET", "POST"])
@login_required
def problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    check = db.execute("SELECT * FROM problems WHERE id=:problem_id AND draft=0",
                       problem_id=problem_id)

    if len(check) != 1 and session["admin"] != 1:
        return render_template("problem/problem_noexist.html"), 404

    # Retrieve problem description and hints
    data[0]["description"] = read_file(
        'metadata/problems/' + problem_id + '/description.md')
    data[0]["hints"] = read_file(
        'metadata/problems/' + problem_id + '/hints.md')
    data[0]["editorial"] = read_file(
        'metadata/problems/' + problem_id + '/editorial.md')

    if request.method == "GET":
        return render_template('problem/problem.html', data=data[0])

    # Reached via POST
    flag = data[0]["flag"]

    if not request.form.get("flag"):
        flash('Cannot submit an empty flag', 'danger')
        return render_template('problem/problem.html', data=data[0]), 400

    check = request.form.get("flag") == flag
    db.execute("INSERT INTO submissions (date, user_id, problem_id, correct) VALUES (datetime('now'), :user_id, :problem_id, :check)",
               user_id=session["user_id"], problem_id=problem_id, check=check)

    if not check:
        flash('The flag you submitted was incorrect', 'danger')
        return render_template('problem/problem.html', data=data[0])

    db.execute("INSERT INTO problem_solved(user_id, problem_id) VALUES(:uid, :pid)",
               uid=session["user_id"], pid=problem_id)

    flash('Congratulations! You have solved this problem!', 'success')
    return render_template('problem/problem.html', data=data[0])


@app.route('/problem/<problem_id>/publish', methods=["POST"])
@admin_required
def publish_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    db.execute("UPDATE problems SET draft=0 WHERE id=:problem_id", problem_id=problem_id)

    flash('Problem successfully published', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problem/<problem_id>/editorial')
@login_required
def problem_editorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    check = db.execute("SELECT * FROM problems WHERE id=:problem_id AND draft=0",
                       problem_id=problem_id)

    if len(check) != 1 and session["admin"] != 1:
        return render_template("problem/problem_noexist.html"), 404

    # Ensure editorial exists
    editorial = read_file('metadata/problems/' + problem_id + '/editorial.md')
    if not editorial:
        return render_template("problem/problem_noeditorial.html"), 404

    return render_template('problem/problemeditorial.html', data=data[0], ed=editorial)


@app.route('/problem/<problem_id>/edit', methods=["GET", "POST"])
@admin_required
def editproblem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    data[0]['description'] = read_file(
        'metadata/problems/' + problem_id + '/description.md')
    data[0]['hints'] = read_file(
        'metadata/problems/' + problem_id + '/hints.md')

    if request.method == "GET":
        return render_template('problem/editproblem.html', data=data[0])

    # Reached via POST

    new_name = request.form.get("name")
    new_description = request.form.get("description")
    new_hint = request.form.get("hints")
    new_category = request.form.get("category")
    new_points = request.form.get("point_value")

    if not new_name or not new_description or not new_category or not new_points:
        flash('You have not entered all required fields', 'danger'), 400
        return render_template('problem/editproblem.html', data=data[0])

    new_description = new_description.replace('\r', '')
    if not new_hint:
        new_hint = ""

    db.execute("UPDATE problems SET name=:name, category=:category, point_value=:pv WHERE id=:problem_id",
               name=new_name, category=new_category, pv=new_points, problem_id=problem_id)
    write_file('metadata/problems/' + problem_id + '/description.md', new_description)
    write_file('metadata/problems/' + problem_id + '/hints.md', new_hint)

    flash('Problem successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problem/<problem_id>/editeditorial', methods=["GET", "POST"])
@admin_required
def problem_editeditorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    data[0]['editorial'] = read_file('metadata/problems/' + problem_id + '/editorial.md')

    if request.method == "GET":
        return render_template('problem/editeditorial.html', data=data[0])

    # Reached via POST

    new_editorial = request.form.get("editorial")
    if not new_editorial:
        new_editorial = ""
    new_editorial = new_editorial.replace('\r', '')

    write_file('metadata/problems/' + problem_id + '/editorial.md', new_editorial)

    flash('Editorial successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problem/<problem_id>/delete', methods=["POST"])
@admin_required
def delete_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    db.execute("BEGIN")
    db.execute("DELETE FROM problems WHERE id=:pid", pid=problem_id)
    db.execute("DELETE FROM problem_solved WHERE problem_id=:pid", pid=problem_id)
    db.execute("COMMIT")
    shutil.rmtree(f"metadata/problems/{problem_id}")

    flash('Problem successfully deleted', 'success')
    return redirect("/problems")


@app.route("/admin/console")
@admin_required
def admin_console():
    return render_template("admin/console.html", maintenance_mode=maintenance_mode)


@csrf.exempt
@app.route("/admin/submissions")
@admin_required
def admin_submissions():
    submissions = None

    modifier = " WHERE"
    args = []

    if request.args.get("username"):
        modifier += " username=? AND"
        args.insert(len(args), request.args.get("username"))

    if request.args.get("problem_id"):
        modifier += " problem_id=? AND"
        args.insert(len(args), request.args.get("problem_id"))

    if request.args.get("contest_id"):
        modifier += " contest_id=? AND"
        args.insert(len(args), request.args.get("contest_id"))

    if request.args.get("correct"):
        modifier += " correct=? AND"
        args.insert(len(args), request.args.get("correct") == "AC")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    if len(args) == 0:
        submissions = db.execute(("SELECT submissions.*, users.username FROM submissions "
                                  "LEFT JOIN users ON user_id=users.id LIMIT 50 "
                                  "OFFSET ?"), page)
        length = len(db.execute("SELECT * FROM submissions"))
    else:
        modifier = modifier[:-4]
        length = len(db.execute(("SELECT submissions.*, users.username FROM submissions "
                                 "LEFT JOIN users ON user_id=users.id") + modifier,
                                *args))
        args.append(page)
        submissions = db.execute(("SELECT submissions.*, users.username FROM submissions "
                                 f"LEFT JOIN users ON user_id=users.id {modifier}"
                                  " LIMIT 50 OFFSET ?"), *args)

    return render_template("admin/submissions.html",
                           data=submissions, length=-(-length // 50))


@app.route("/admin/users")
@admin_required
def admin_users():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    data = db.execute("SELECT * FROM users LIMIT 50 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM users"))
    return render_template("admin/users.html", data=data, length=-(-length // 50))


@app.route("/admin/createcontest", methods=["GET", "POST"])
@admin_required
def admin_createcontest():
    if request.method == "GET":
        return render_template("admin/createcontest.html")

    # Reached using POST

    contest_id = request.form.get("contest_id")

    # Ensure contest ID is valid
    if not verify_text(contest_id):
        flash('Invalid contest ID', 'danger')
        return render_template("admin/createcontest.html"), 400

    contest_name = request.form.get("contest_name")

    # Ensure contest doesn't already exist
    check = db.execute("SELECT * FROM contests WHERE id=:contest_id OR name=:contest_name",  ## noqa E501
                       contest_id=contest_id, contest_name=contest_name)
    if len(check) != 0:
        flash('A contest with that name or ID already exists', 'danger')
        return render_template("admin/createcontest.html"), 409

    start = request.form.get("start")
    end = request.form.get("end")

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("admin/createcontest.html"), 400

    description = request.form.get("description").replace('\r', '')
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))
    if not description:
        flash('Description cannot be empty', 'danger')
        return render_template("admin/createcontest.html"), 400

    db.execute("INSERT INTO contests (id, name, start, end, scoreboard_visible) VALUES (:id, :name, datetime(:start), datetime(:end), :scoreboard_visible)",
               id=contest_id, name=contest_name, start=start, end=end,
               scoreboard_visible=scoreboard_visible)

    os.makedirs('metadata/contests/' + contest_id)
    write_file('metadata/contests/' + contest_id + '/description.md', description)

    flash('Contest successfully created', 'success')
    return redirect("/contest/" + contest_id)


@app.route("/admin/createproblem", methods=["GET", "POST"])
@admin_required
def createproblem():
    if request.method == "GET":
        return render_template("admin/createproblem.html")

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description = request.form.get("description")
    hints = request.form.get("hints")
    point_value = request.form.get("point_value")
    category = request.form.get("category")
    flag = request.form.get("flag")
    draft = 1 if request.form.get("draft") else 0

    if not problem_id or not name or not description or not point_value or not category or not flag:
        flash('You have not entered all required fields', 'danger')
        return render_template("admin/createproblem.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("admin/createproblem.html"), 400

    description = description.replace('\r', '')
    if not hints:
        hints = ""

    # Ensure problem does not already exist
    problem_info = db.execute("SELECT * FROM problems WHERE id=:problem_id OR name=:name",
                              problem_id=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("admin/createproblem.html"), 409

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        filename = problem_id + ".zip"
        file.save("dl/" + filename)
        description += f'\n\n[{filename}](/dl/{filename})'

    # Modify problems table
    db.execute("INSERT INTO problems (id, name, point_value, category, flag, draft) VALUES (:id, :name, :point_value, :category, :flag, :draft)",
               id=problem_id, name=name, point_value=point_value, category=category,
               flag=flag, draft=draft)

    os.makedirs('metadata/problems/' + problem_id)
    write_file('metadata/problems/' + problem_id + '/description.md', description)
    write_file('metadata/problems/' + problem_id + '/hints.md', hints)
    open('metadata/problems/' + problem_id + '/editorial.md', 'w').close()

    flash('Problem successfully created', 'success')
    return redirect("/problem/" + problem_id)


@app.route("/admin/ban", methods=["POST"])
@admin_required
def ban():
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    user_id = int(user_id)
    user = user[0]

    if user_id == session["user_id"]:
        flash("Cannot ban yourself", "danger")
        return redirect("/admin/users")

    if user["admin"] and session["user_id"] != 1:
        flash("Only the super-admin can ban admins", "danger")
        return redirect("/admin/users")

    db.execute("UPDATE users SET banned=:status WHERE id=:id",
               status=not user["banned"], id=user_id)

    if user["banned"]:
        flash("Successfully unbanned " + user["username"], "success")
    else:
        flash("Successfully banned " + user["username"], "success")

    return redirect("/admin/users")


@app.route("/admin/resetpass", methods=["POST"])
@admin_required
def reset_password():
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    password = generate_password()
    db.execute("UPDATE users SET password=:p WHERE id=:id",
               p=generate_password_hash(password), id=user_id)

    flash("Password for " + user[0]["username"] + " resetted! Their new password is " + password, "success")
    return redirect("/admin/users")


@app.route("/admin/makeadmin", methods=["POST"])
@admin_required
def makeadmin():
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    user_id = int(user_id)
    admin_status = user[0]["admin"]

    if admin_status and session["user_id"] != 1:
        flash("Only the super-admin can revoke admin status", "danger")
        return redirect("/admin/users")

    if admin_status and user_id == 1:
        flash("Cannot revoke super-admin privileges", "danger")
        return redirect("/admin/users")

    if admin_status and session["user_id"] == 1:
        db.execute("UPDATE users SET admin=0 WHERE id=:id", id=user_id)
        flash("Admin privileges for " + user[0]["username"] + " revoked", "success")
        return redirect("/admin/users")
    else:
        db.execute("UPDATE users SET admin=1 WHERE id=:id", id=user_id)
        flash("Admin privileges for " + user[0]["username"] + " granted", "success")
        return redirect("/admin/users")


@app.route("/admin/createannouncement", methods=["GET", "POST"])
@admin_required
def createannouncement():
    if request.method == "GET":
        return render_template("admin/createannouncement.html")

    # Reached via POST

    if not request.form.get("name") or not request.form.get("description"):
        flash('You have not entered all required fields', 'danger')
        return render_template("admin/createannouncement.html"), 400

    name = request.form.get("name")
    description = request.form.get("description").replace('\r', '')

    db.execute("INSERT INTO announcements (name, date) VALUES (:name, datetime('now'))",
               name=name)
    aid = db.execute("SELECT * FROM announcements ORDER BY date DESC")[0]["id"]

    write_file('metadata/announcements/' + str(aid) + '.md', description)

    flash('Announcement successfully created', 'success')
    return redirect("/")


@app.route("/admin/deleteannouncement", methods=["POST"])
@admin_required
def delete_announcement():
    aid = request.form.get("aid")
    if not aid:
        return "Must provide announcement ID", 400

    db.execute("DELETE FROM announcements WHERE id=:id", id=aid)
    os.remove('metadata/announcements/' + aid + '.md')

    flash('Announcement successfully deleted', 'success')
    return redirect("/")


@app.route("/admin/deletecontest/<contest_id>", methods=["GET", "POST"])
@admin_required
def delete_contest(contest_id):
    # Ensure contest exists
    check = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(check) == 0:
        return render_template("contest/contest_noexist.html")

    if request.method == "GET":
        return render_template("contest/delete_confirm.html", data=check[0])

    # Reached using POST

    db.execute("BEGIN")
    db.execute("DELETE FROM contests WHERE id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_users WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_problems WHERE contest_id=:cid", cid=contest_id)
    db.execute("COMMIT")

    shutil.rmtree('metadata/contests/' + contest_id)

    flash('Contest successfully deleted', 'success')
    return redirect("/contests")


@app.route('/admin/editannouncement/<aid>', methods=["GET", "POST"])
@admin_required
def editannouncement(aid):
    data = db.execute("SELECT * FROM announcements WHERE id=:aid", aid=aid)

    # Ensure announcement exists
    if len(data) == 0:
        flash('That announcement does not exist', 'danger')
        return redirect("/")

    data[0]["description"] = read_file('metadata/announcements/' + aid + '.md')

    if request.method == "GET":
        return render_template('admin/editannouncement.html', data=data[0])

    # Reached via POST
    new_name = request.form.get("name")
    new_description = request.form.get("description").replace('\r', '')

    if not new_name:
        flash('Name cannot be empty', 'danger')
        return render_template('admin/editannouncement.html', data=data[0]), 400
    if not new_description:
        flash('Description cannot be empty', 'danger')
        return render_template('admin/editannouncement.html', data=data[0]), 400

    # Update database
    db.execute("UPDATE announcements SET name=:name WHERE id=:aid",
               name=new_name, aid=aid)

    write_file('metadata/announcements/' + aid + '.md', new_description)

    flash('Announcement successfully edited', 'success')
    return redirect("/")


@app.route('/admin/editcontest/<contest_id>', methods=["GET", "POST"])
@admin_required
def editcontest(contest_id):
    data = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)

    # Ensure contest exists
    if len(data) == 0:
        flash('That contest does not exist', 'danger')
        return redirect("/contests")

    data[0]["description"] = read_file(
        'metadata/contests/' + contest_id + '/description.md')

    if request.method == "GET":
        return render_template('admin/editcontest.html', data=data[0])

    # Reached via POST
    new_name = request.form.get("name")
    new_description = request.form.get("description").replace('\r', '')
    start = request.form.get("start")
    end = request.form.get("end")

    if not new_name:
        flash('Name cannot be empty', 'danger')
        return render_template('admin/editcontest.html', data=data[0]), 400
    if not new_description:
        flash('Description cannot be empty', 'danger')
        return render_template('admin/editcontest.html', data=data[0]), 400

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("admin/editcontest.html"), 400

    db.execute("UPDATE contests SET name=:name, start=datetime(:start), end=datetime(:end) WHERE id=:cid",
               name=new_name, start=start, end=end, cid=contest_id)

    write_file('metadata/contests/' + contest_id + '/description.md', new_description)

    flash('Contest successfully edited', 'success')
    return redirect("/contests")


@app.route("/admin/maintenance", methods=["POST"])
@admin_required
def maintenance():
    global maintenance_mode
    maintenance_mode = not maintenance_mode

    if maintenance_mode:
        flash("Enabled maintenance mode", "success")
    else:
        flash("Disabled maintenance mode", "success")

    return redirect('/admin/console')


# Error handling
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    if e.code == 404:
        return render_template("error/404.html"), 404
    if e.code == 500:
        return render_template("error/500.html"), 500
    return render_template("error/generic.html", e=e), e.code


for code in default_exceptions:
    app.errorhandler(code)(errorhandler)


@app.route("/teapot")
def teapot():
    return render_template("error/418.html"), 418


# Security headers
@app.after_request
def security_policies(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response
