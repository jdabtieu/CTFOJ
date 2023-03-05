import logging
import os
import requests
import shutil
import sys
import zipfile
from datetime import datetime
from io import BytesIO

import jwt
from cs50 import SQL
from flask import (Flask, flash, redirect, render_template, request,
                   send_from_directory, send_file, session)
from flask_mail import Mail
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException, InternalServerError, default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *  # noqa

app = Flask(__name__)

try:
    app.config.from_object('settings')
except Exception as e:
    sys.stderr.write(str(e))
    app.config.from_object('default_settings')
app.jinja_env.globals['CLUB_NAME'] = app.config['CLUB_NAME']
app.jinja_env.globals['USE_CAPTCHA'] = app.config['USE_CAPTCHA']

# Configure logging
LOG_HANDLER = logging.FileHandler(app.config['LOGGING_FILE_LOCATION'])
LOG_HANDLER.setFormatter(
    logging.Formatter(fmt="[CTFOJ] [{section}] [{levelname}] [{asctime}] {message}",
                      style='{'))
logger = logging.getLogger("CTFOJ")
logger.addHandler(LOG_HANDLER)
logger.propagate = False
for handler in logging.root.handlers[:]:
    logging.root.removeHandler(handler)
logging.basicConfig(
    filename=app.config['LOGGING_FILE_LOCATION'],
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
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

# Load API
from api import api  # noqa
app.register_blueprint(api, url_prefix="/api")

# Validate settings
if not app.config['TESTING']:
    with app.app_context():
        try:
            send_email('CTFOJ Email Setup', app.config['MAIL_DEFAULT_SENDER'],
                       [app.config['MAIL_DEFAULT_SENDER']],
                       ('This email tests your configured email settings for CTFOJ. '
                        '<b>Please note that HTML is supported.</b> '
                        'Please ignore this email.'))
        except Exception as error:
            logging.warning("Settings validation: Email credentials invalid.")
            logging.warning(str(error))
        else:
            logging.debug("Settings validation: Email credentials valid.")
        if app.config['USE_CAPTCHA']:
            captcha = requests.post('https://hcaptcha.com/siteverify', data={
                'secret': app.config['HCAPTCHA_SECRET'],
                'response': "placeholder",
                'sitekey': app.config['HCAPTCHA_SITE']
            })
            if len(captcha.json()["error-codes"]) == 1:  # only error is invalid input
                logging.debug("Settings validation: hCaptcha credentials valid.")
            else:
                logging.warning("Settings validation: hCaptcha credentials invalid.")
        if app.config['USE_HOMEPAGE']:
            if os.path.isfile(app.config['HOMEPAGE_FILE']):
                logging.debug("Settings validation: Homepage file exists.")
            else:
                logging.warning("Settings validation: Homepage file nonexistent.")


@app.before_request
def check_for_maintenance():
    # Don't prevent login or getting assets
    if request.path == '/login' or (request.path[:8] == '/assets/'
                                    and '..' not in request.path):
        return

    maintenance_mode = bool(os.path.exists('maintenance_mode'))
    if maintenance_mode:
        if request.path[:5] == '/api/':
            return make_response(("The site is currently undergoing maintenance", 503))

        # Prevent Internal Server error if session only contains CSRF token
        if not session or 'admin' not in session:
            return render_template("error/maintenance.html"), 503
        elif not session['admin']:
            return render_template("error/maintenance.html"), 503
        else:
            flash("Maintenance mode is enabled", "warning")


@app.route("/")
def index():
    # Redirect to login page if homepage setting disabled
    if not app.config["USE_HOMEPAGE"] and (not session or 'username' not in session):
        return redirect("/login")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 10

    data = db.execute(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM announcements"))

    if not session or 'username' not in session:
        template = read_file(app.config['HOMEPAGE_FILE'])
        template_type = int(template[0])
        return render_template(f"home_fragment/home{template_type}.html",
                               data=data,
                               length=-(-length // 10))
    else:
        return render_template("index.html", data=data, length=-(-length // 10))


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")


@app.route("/docs")
def docs():
    return redirect(app.config['DOCS_URL'])


@app.route("/assets/<path:filename>")
def get_asset(filename):
    resp = send_from_directory("assets/", filename)
    resp.headers['Cache-Control'] = 'max-age=604800, must-revalidate'
    return resp


@app.route("/dl/<path:filename>")
@login_required
def dl(filename):
    return send_from_directory("dl/", filename, as_attachment=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    # Forget user id
    session.clear()
    session.permanent = True  # Have to re-set this after clear

    if request.method == "GET":
        return render_template("auth/login.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    # Ensure username and password were submitted
    if not request.form.get("username") or not request.form.get("password"):
        flash('Username and password cannot be blank', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/login.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure user is allowed to log in
    rows = db.execute("SELECT * FROM users WHERE username=:username",
                      username=request.form.get("username"))
    code = login_chk(rows)
    if code != 0:
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), code

    # implement 2fa verification via email
    if rows[0]["twofa"]:
        email = rows[0]["email"]
        token = create_jwt({'email': email}, app.config['SECRET_KEY'])
        text = render_template('email/confirm_login.html',
                               username=request.form.get('username'), token=token)

        if not app.config['TESTING']:
            send_email('CTFOJ Login Confirmation',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text)

        flash(('A login confirmation email has been sent to the email address you '
               'provided. Be sure to check your spam folder!'), 'success')
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) initiated 2FA "
                     f"on IP {request.remote_addr}"), extra={"section": "auth"})
        return render_template("auth/login.html", site_key=app.config['HCAPTCHA_SITE'])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["admin"] = rows[0]["admin"]

    logger.info((f"User #{session['user_id']} ({session['username']}) logged in "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    # Redirect user to next page
    next_url = request.form.get("next")
    if next_url and '//' not in next_url and ':' not in next_url:
        return redirect(next_url)
    return redirect('/')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("auth/register.html", site_key=app.config['HCAPTCHA_SITE'])

    # Reached using POST

    username = request.form.get("username")
    password = request.form.get("password")
    confirmation = request.form.get("confirmation")
    email = request.form.get("email")

    # Ensure username is valid
    if not username or not verify_text(username):
        flash('Invalid username', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure password is not blank
    if not password or len(password) < 8:
        flash('Password must be at least 8 characters', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    # Ensure email is valid
    if "+" in email:
        flash('Plus character not allowed in email', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400
    email = email.lower()
    
    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/register.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400
    
    # Ensure username and email do not already exist
    rows = db.execute("SELECT * FROM users WHERE username = :username", username=username)
    if len(rows) > 0:
        flash('Username already exists', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 409

    rows = db.execute("SELECT * FROM users WHERE email = :email", email=email)
    if len(rows) > 0:
        flash('Email already exists', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 409

    token = create_jwt({'email': email}, app.config['SECRET_KEY'])
    text = render_template('email/confirm_account.html',
                           username=username, token=token)

    db.execute(("INSERT INTO users(username, password, email, join_date) "
                "VALUES(:username, :password, :email, datetime('now'))"),
               username=username, password=generate_password_hash(password), email=email)
    if not app.config['TESTING']:
        send_email('CTFOJ Account Confirmation',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text)

    flash(('An account creation confirmation email has been sent to the email address '
           'you provided. Be sure to check your spam folder!'), 'success')
    logger.info((f"User {username} ({email}) has initiated a registration request "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return render_template("auth/register.html", site_key=app.config['HCAPTCHA_SITE'])


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
        flash("Email verification link expired. Please register again using the same email.",  # noqa
              "danger")
        return redirect("/register")

    db.execute("UPDATE users SET verified=1 WHERE email=:email", email=token['email'])

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email = :email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = False  # ensure no one can get admin right after registering

    logger.info((f"User #{session['user_id']} ({session['username']}) has successfully "
                 f"registered on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/problem/helloworld")


@app.route('/cancelregister/<token>')
def cancel_register(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0
    if not token:
        flash("Email verification link invalid", "danger")
        return redirect("/register")
    db.execute(
        "DELETE FROM users WHERE verified=0 and email=:email", email=token['email'])
    flash("Your registration has been successfully removed from our database.", "success")
    logger.info((f"User with email {token['email']} has cancelled "
                 f"registration on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/register")


@app.route('/confirmlogin/<token>')
def confirm_login(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception as e:
        sys.stderr.write(str(e))
        token = 0

    if not token:
        flash('Invalid login verification link', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Login verification link expired; Please re-login', 'danger')
        return render_template("auth/login.html",
                               site_key=app.config['HCAPTCHA_SITE']), 401

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email = :email", email=token['email'])[0]
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["admin"] = user["admin"]

    logger.info((f"User #{session['user_id']} ({session['username']}) logged in via 2FA "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    return redirect("/")


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


@app.route("/settings/changepassword", methods=["GET", "POST"])
@login_required
def changepassword():
    if request.method == "GET":
        return render_template("auth/changepassword.html")

    # Reached using POST

    old_password = request.form.get("password")
    new_password = request.form.get("newPassword")
    confirmation = request.form.get("confirmation")

    # Ensure passwords were submitted and they match
    if not old_password:
        flash('Password cannot be blank', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/changepassword.html"), 400
    if not confirmation or new_password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/changepassword.html"), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], old_password):
        flash('Incorrect password', 'danger')
        return render_template("auth/changepassword.html"), 401

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(new_password), id=session["user_id"])

    logger.info((f"User #{session['user_id']} ({session['username']}) has changed "
                 "their password"), extra={"section": "auth"})
    flash("Password change successful", "success")
    return redirect("/settings")


@app.route("/settings/toggle2fa", methods=["GET", "POST"])
@login_required
def toggle2fa():
    user = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])[0]

    if request.method == "GET":
        return render_template("toggle2fa.html", status=user["twofa"])

    # Reached via POST

    password = request.form.get("password")

    if not password or not check_password_hash(user['password'], password):
        flash('Incorrect password', 'danger')
        return render_template("toggle2fa.html", status=user["twofa"]), 401

    msg = "disabled" if user["twofa"] else "enabled"
    if user["twofa"]:
        db.execute("UPDATE users SET twofa=0 WHERE id=:id", id=session["user_id"])
    else:
        db.execute("UPDATE users SET twofa=1 WHERE id=:id", id=session["user_id"])
    flash("2FA successfully " + msg, "success")
    logger.info(f"User #{session['user_id']} ({session['username']}) {msg} 2FA",
                extra={"section": "auth"})
    return redirect("/settings")


@app.route("/forgotpassword", methods=["GET", "POST"])
def forgotpassword():
    if request.method == "GET":
        return render_template("auth/forgotpassword.html",
                               site_key=app.config['HCAPTCHA_SITE'])

    # Reached via POST

    email = request.form.get("email")
    if not email:
        flash('Email cannot be blank', 'danger')
        return render_template("auth/forgotpassword.html"), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/forgotpassword.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    rows = db.execute("SELECT * FROM users WHERE email = :email",
                      email=request.form.get("email"))

    if len(rows) == 1:
        token = create_jwt({'user_id': rows[0]["id"]}, app.config['SECRET_KEY'])
        text = render_template('email/reset_password.html',
                               username=rows[0]["username"], token=token)
        logger.info((f"User #{rows[0]['id']} ({rows[0]['username']}) initiated a "
                     f"password reset from IP {request.remote_addr}"),
                    extra={"section": "auth"})
        if not app.config['TESTING']:
            send_email('CTFOJ Password Reset',
                       app.config['MAIL_DEFAULT_SENDER'], [email], text)

    flash(('If there is an account associated with that email, a password reset email '
           'has been sent'), 'success')
    return render_template("auth/forgotpassword.html")


@app.route('/resetpassword/<token>', methods=['GET', 'POST'])
def reset_password_user(token):
    try:
        token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = token['user_id']
    except Exception as e:
        sys.stderr.write(str(e))
        user_id = 0
    if not user_id or datetime.strptime(token["expiration"],
                                        "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        flash('Password reset link expired/invalid', 'danger')
        return redirect('/forgotpassword')

    if request.method == "GET":
        return render_template('auth/resetpassword.html')

    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not password or len(password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/resetpassword.html"), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/resetpassword.html"), 400

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(password), id=user_id)

    logger.info((f"User #{user_id} completed a password reset from "
                 f"IP {request.remote_addr}"), extra={"section": "auth"})
    flash('Your password has been successfully reset', 'success')
    return redirect("/login")


@app.route("/contests")
@login_required
def contests():
    past = db.execute(
        "SELECT * FROM contests WHERE end < datetime('now') ORDER BY end DESC")
    current = db.execute(
        ("SELECT * FROM contests WHERE end > datetime('now') AND "
         "start <= datetime('now') ORDER BY end DESC"))
    future = db.execute(
        "SELECT * FROM contests WHERE start > datetime('now') ORDER BY start DESC")
    return render_template("contest/contests.html",
                           past=past, current=current, future=future)


@app.route("/contests/create", methods=["GET", "POST"])
@admin_required
def create_contest():
    if request.method == "GET":
        return render_template("contest/create.html")

    # Reached using POST

    contest_id = request.form.get("contest_id")

    # Ensure contest ID is valid
    if not contest_id or not verify_text(contest_id) or contest_id == "None":
        flash('Invalid contest ID', 'danger')
        return render_template("contest/create.html"), 400

    contest_name = request.form.get("contest_name")

    # Ensure contest doesn't already exist
    check = db.execute("SELECT * FROM contests WHERE id=:cid OR name=:contest_name",
                       cid=contest_id, contest_name=contest_name)
    if len(check) != 0:
        flash('A contest with that name or ID already exists', 'danger')
        return render_template("contest/create.html"), 409

    start = request.form.get("start")
    end = request.form.get("end")

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("contest/create.html"), 400

    description = request.form.get("description").replace('\r', '')
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))
    if not description:
        flash('Description cannot be empty', 'danger')
        return render_template("contest/create.html"), 400

    db.execute(
        ("INSERT INTO contests (id, name, start, end, scoreboard_visible) "
         "VALUES (:id, :name, datetime(:start), datetime(:end), :scoreboard_visible)"),
        id=contest_id, name=contest_name, start=start, end=end,
        scoreboard_visible=scoreboard_visible)

    os.makedirs('metadata/contests/' + contest_id)
    write_file('metadata/contests/' + contest_id + '/description.md', description)

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully created', 'success')
    return redirect("/contest/" + contest_id)


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

    user_info = db.execute(
        "SELECT * FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])

    if len(user_info) == 0 and datetime.utcnow() < datetime.strptime(contest_info[0]["end"], "%Y-%m-%d %H:%M:%S"):
        db.execute("INSERT INTO contest_users (contest_id, user_id) VALUES(:cid, :uid)",
                   cid=contest_id, uid=session["user_id"])
        db.execute("UPDATE users SET contests_completed=contests_completed+1 WHERE id=?",
                   session["user_id"])

    solved_info = db.execute(
        "SELECT problem_id FROM contest_solved WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])

    solved_data = set()
    for row in solved_info:
        solved_data.add(row["problem_id"])

    data = []
    info = db.execute(
        ("SELECT * FROM contest_problems WHERE contest_id=:cid AND draft=0 "
         "GROUP BY problem_id ORDER BY problem_id ASC, category ASC;"),
        cid=contest_id)

    solve_count = dict()
    for row in db.execute(("SELECT problem_id, COUNT(user_id) AS solves FROM "
                           "contest_solved WHERE contest_id=:cid AND user_id NOT IN ("
                           "SELECT user_id FROM contest_users WHERE contest_id=:cid AND "
                           "hidden=1) GROUP BY problem_id"), cid=contest_id):
        if row["problem_id"] is None:
            continue
        solve_count[row["problem_id"]] = row["solves"]

    for row in info:
        problem_id = row["problem_id"]
        keys = {
            "name": row["name"],
            "category": row["category"],
            "problem_id": problem_id,
            "solved": 1 if problem_id in solved_data else 0,
            "point_value": row["point_value"],
            "sols": solve_count[problem_id] if problem_id in solve_count else 0,
            "dynamic": 0 if row["score_users"] == -1 else 1,
        }
        data.append(keys)

    return render_template("contest/contest.html", title=title, scoreboard=scoreboard,
                           data=data)


@app.route('/contest/<contest_id>/edit', methods=["GET", "POST"])
@admin_required
def editcontest(contest_id):
    data = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)

    # Ensure contest exists
    if len(data) == 0:
        flash('That contest does not exist', 'danger')
        return redirect("/contests")

    if request.method == "GET":
        return render_template('contest/edit.html', data=data[0])

    # Reached via POST
    new_name = request.form.get("name")
    new_description = request.form.get("description").replace('\r', '')
    start = request.form.get("start")
    end = request.form.get("end")
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))

    if not new_name:
        flash('Name cannot be empty', 'danger')
        return render_template('contest/edit.html', data=data[0]), 400
    if not new_description:
        flash('Description cannot be empty', 'danger')
        return render_template('contest/edit.html', data=data[0]), 400

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("contest/edit.html"), 400

    db.execute(("UPDATE contests SET name=?, start=datetime(?), end=datetime(?), "
                "scoreboard_visible=? WHERE id=?"),
               new_name, start, end, scoreboard_visible, contest_id)

    write_file(f'metadata/contests/{contest_id}/description.md', new_description)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully edited', 'success')
    return redirect("/contests")


@app.route("/contest/<contest_id>/delete", methods=["GET", "POST"])
@admin_required
def delete_contest(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html")

    if request.method == "GET":
        return render_template("contest/delete_confirm.html", data=contest_id)

    # Reached using POST

    db.execute("BEGIN")
    db.execute("DELETE FROM contests WHERE id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_users WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=:cid", cid=contest_id)
    db.execute("DELETE FROM contest_problems WHERE contest_id=:cid", cid=contest_id)
    db.execute("COMMIT")

    shutil.rmtree('metadata/contests/' + contest_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully deleted', 'success')
    return redirect("/contests")


@app.route("/contest/<contest_id>/notify", methods=['GET', 'POST'])
@admin_required
def contest_notify(contest_id):
    if request.method == "GET":
        return render_template('contest/notify.html')

    subject = request.form.get("subject")
    if not subject:
        flash('Must provide subject', 'danger')
        return render_template('contest/notify.html'), 400
    message = request.form.get("message")
    if not message:
        flash('Must provide message', 'danger')
        return render_template('contest/notify.html'), 400

    data = db.execute(("SELECT email FROM contest_users JOIN users on user_id=users.id "
                       "WHERE contest_users.contest_id=:cid"),
                      cid=contest_id)
    emails = [participant["email"] for participant in data]
    if not app.config['TESTING']:
        send_email(subject, app.config['MAIL_DEFAULT_SENDER'], [], message, emails)

    logger.info((f"User #{session['user_id']} ({session['username']}) sent a "
                 f"notification email to participants of contest {contest_id}"),
                extra={"section": "problem"})
    flash('Participants successfully notified', 'success')
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
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest started or user is admin
    check = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    start = datetime.strptime(check[0]["start"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() < start and not session["admin"]:
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    check = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                        "problem_id=:pid"),
                       cid=contest_id, pid=problem_id)
    if len(check) != 1 or (check[0]["draft"] and not session["admin"]):
        return render_template("contest/contest_problem_noexist.html"), 404

    # Check if problem is solved
    check[0]["solved"] = len(db.execute(
        ("SELECT * FROM contest_solved WHERE contest_id=:cid AND "
         "problem_id=:pid AND user_id=:uid"),
        cid=contest_id, pid=problem_id, uid=session["user_id"])) == 1

    if request.method == "GET":
        return render_template("contest/contest_problem.html", data=check[0])

    # Reached via POST

    # Ensure contest hasn't ended
    if contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)):
        flash('This contest has ended', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    # Check if user is disqualified and in the contest
    user = db.execute(
        "SELECT * FROM contest_users WHERE user_id=:uid AND contest_id=:cid",
        uid=session["user_id"], cid=contest_id)
    if len(user) > 0 and user[0]["points"] == -999999:
        flash('You are disqualified from this contest', 'danger')
        return render_template("contest/contest_problem.html", data=check[0])
    if len(user) == 0:
        db.execute("INSERT INTO contest_users(contest_id, user_id) VALUES (:cid, :uid)",
                   cid=contest_id, uid=session["user_id"])

    flag = request.form.get("flag")
    if not flag or not verify_flag(flag):
        flash('Invalid flag', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    db.execute(
        ("INSERT INTO submissions(date, user_id, problem_id, contest_id, correct, "
         "submitted) VALUES(datetime('now'), :uid, :pid, :cid, :correct, :flag)"),
        uid=session["user_id"], pid=problem_id, cid=contest_id,
        correct=(flag == check[0]["flag"]), flag=flag)

    # Check if flag is correct
    if flag != check[0]["flag"]:
        flash('Your flag is incorrect', 'danger')
        return render_template("contest/contest_problem.html", data=check[0])

    # Check if user has already found this flag
    check1 = db.execute(("SELECT * FROM contest_solved WHERE contest_id=:cid "
                         "AND user_id=:uid AND problem_id=:pid"),
                        cid=contest_id, uid=session["user_id"], pid=problem_id)
    if len(check1) == 0:
        db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                    "VALUES(:cid, :uid, :pid)"),
                   cid=contest_id, pid=problem_id, uid=session["user_id"])

        if check[0]["score_users"] != -1:  # Dynamic scoring
            update_dyn_score(contest_id, problem_id)
        else:  # Static scoring
            points = check[0]["point_value"]
            db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
                        "points=points+:points WHERE contest_id=:cid AND user_id=:uid"),
                       cid=contest_id, points=points, uid=session["user_id"])

    check[0]["solved"] = True
    flash('Congratulations! You have solved this problem!', 'success')
    return render_template("contest/contest_problem.html", data=check[0])


@app.route("/contest/<contest_id>/problem/<problem_id>/publish", methods=["POST"])
@admin_required
def publish_contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    check = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)

    if len(check) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    db.execute(
        "UPDATE contest_problems SET draft=0 WHERE problem_id=:pid AND contest_id=:cid",
        pid=problem_id, cid=contest_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) published "
                 f"{problem_id} from contest {contest_id}"), extra={"section": "contest"})
    flash('Problem successfully published', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@app.route('/contest/<contest_id>/problem/<problem_id>/edit', methods=["GET", "POST"])
@admin_required
def edit_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        return render_template('contest/edit_problem.html', data=data[0])

    # Reached via POST

    new_name = request.form.get("name")
    new_description = request.form.get("description")
    new_hint = request.form.get("hints")
    new_category = request.form.get("category")
    new_points = request.form.get("point_value")
    new_flag = request.form.get("flag")
    new_flag_hint = request.form.get("flag-hint")
    if not new_flag_hint:
        new_flag_hint = ""

    if (not new_name or not new_description or not new_category
            or (not new_points and data[0]["score_users"] == -1)):
        flash('You have not entered all required fields', 'danger')
        return render_template('contest/edit_problem.html', data=data[0]), 400

    if new_flag:
        if not verify_flag(new_flag):
            flash('Invalid flag', 'danger')
            return render_template('contest/edit_problem.html', data=data[0]), 400
        if request.form.get("rejudge"):
            rejudge_contest_problem(contest_id, problem_id, new_flag)
    else:
        new_flag = data[0]["flag"]
        new_flag_hint = data[0]["flag_hint"]

    new_description = new_description.replace('\r', '')
    if not new_hint:
        new_hint = ""

    # Only edit score for statically scored problems whose value has changed
    if data[0]["score_users"] == -1 and data[0]["point_value"] != new_points:
        point_change = int(new_points) - data[0]["point_value"]
        db.execute(("UPDATE contest_users SET points=points+:point_change WHERE "
                    "contest_id=:cid AND user_id IN (SELECT user_id FROM contest_solved "
                    "WHERE contest_id=:cid AND problem_id=:pid)"),
                   point_change=point_change, cid=contest_id, pid=problem_id)
        db.execute(("UPDATE contest_problems SET point_value=:pv WHERE contest_id=:cid "
                    "AND problem_id=:pid"),
                   pv=int(new_points), cid=contest_id, pid=problem_id)

    db.execute(("UPDATE contest_problems SET name=:name, category=:category, flag=:flag, "
                "flag_hint=:fhint WHERE contest_id=:cid AND problem_id=:pid"),
               name=new_name, category=new_category, flag=new_flag, cid=contest_id,
               pid=problem_id, fhint=new_flag_hint)

    write_file(
        f'metadata/contests/{contest_id}/{problem_id}/description.md', new_description)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', new_hint)

    logger.info((f"User #{session['user_id']} ({session['username']}) edited problem "
                 f"{problem_id} in contest {contest_id}"),
                extra={"section": "contest"})
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

    data = db.execute(
        ("SELECT user_id, points, lastAC, username FROM contest_users "
         "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
         "hidden=0 ORDER BY points DESC, lastAC ASC"),
        cid=contest_id)

    if session["admin"]:
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 ORDER BY points DESC, lastAC ASC"),
            cid=contest_id)
    else:
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 AND user_id=:uid ORDER BY points DESC, lastAC ASC"),
            cid=contest_id, uid=session["user_id"])

    return render_template("contest/scoreboard.html",
                           title=contest_info[0]["name"], data=data, hidden=hidden)


@app.route("/contest/<contest_id>/scoreboard/ban", methods=["POST"])
@admin_required
def contest_dq(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET points=-999999 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)

    logger.info((f"User #{user_id} banned from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@app.route("/contest/<contest_id>/scoreboard/hide", methods=["POST"])
@admin_required
def contest_hide(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET hidden=1 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)

    logger.info((f"User #{user_id} hidden from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@app.route("/contest/<contest_id>/scoreboard/unhide", methods=["POST"])
@admin_required
def contest_unhide(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute(
        "UPDATE contest_users SET hidden=0 WHERE user_id=:uid AND contest_id=:cid",
        uid=user_id, cid=contest_id)

    logger.info((f"User #{user_id} unhidden from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@app.route("/contest/<contest_id>/addproblem", methods=["GET", "POST"])
@admin_required
def contest_add_problem(contest_id):
    # Ensure contest exists
    contest_info = db.execute(
        "SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest hasn't ended
    if contest_ended(contest_info):
        flash('This contest has already ended', 'danger')
        return redirect('/contest/' + contest_id)

    if request.method == "GET":
        return render_template("contest/create_problem.html")

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description = request.form.get("description")
    hints = request.form.get("hints")
    category = request.form.get("category")
    flag = request.form.get("flag")
    draft = 1 if request.form.get("draft") else 0
    flag_hint = request.form.get("flag-hint")
    if not flag_hint:
        flag_hint = ""

    if not problem_id or not name or not description or not category or not flag:
        flash('You have not entered all required fields', 'danger')
        return render_template("contest/create_problem.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("contest/create_problem.html"), 400

    # Check if flag is valid
    if not verify_flag(flag):
        flash('Invalid flag', 'danger')
        return render_template("contest/create_problem.html"), 400

    # Ensure problem does not already exist
    problem_info = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                               "(problem_id=:pid OR name=:name)"),
                              cid=contest_id, pid=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("contest/create_problem.html"), 409

    description = description.replace('\r', '')

    # Check for static vs dynamic scoring
    score_type = request.form.get("score_type")
    if score_type == "dynamic":
        min_points = request.form.get("min_point_value")
        max_points = request.form.get("max_point_value")
        users_decay = request.form.get("users_point_value")
        if not min_points or not max_points or not users_decay:
            flash('You have not entered all required fields', 'danger')
            return render_template("contest/create_problem.html"), 400

        # Modify problems table
        db.execute(("INSERT INTO contest_problems VALUES(:cid, :pid, :name, :pv, "
                    ":category, :flag, :draft, :min, :max, :users, :fhint)"),
                   cid=contest_id, pid=problem_id, name=name, pv=max_points,
                   category=category, flag=flag, draft=draft, min=min_points,
                   max=max_points, users=users_decay, fhint=flag_hint)
    else:  # assume static
        point_value = request.form.get("point_value")
        if not point_value:
            flash('You have not entered all required fields', 'danger')
            return render_template("contest/create_problem.html"), 400

        # Modify problems table
        db.execute(("INSERT INTO contest_problems(contest_id, problem_id, name, "
                    "point_value, category, flag, draft, flag_hint) "
                    "VALUES(:cid, :pid, :name, :pv, :category, :flag, :draft, :fhint)"),
                   cid=contest_id, pid=problem_id, name=name, pv=point_value,
                   category=category, flag=flag, draft=draft, fhint=flag_hint)

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        if not os.path.exists("dl/" + contest_id):
            os.makedirs("dl/" + contest_id)
        filename = problem_id + ".zip"
        filepath = "dl/" + contest_id + "/"
        file.save(filepath + filename)
        description += f'\n\n[{filename}](/{filepath + filename})'

    os.makedirs(f'metadata/contests/{contest_id}/{problem_id}')
    write_file(f'metadata/contests/{contest_id}/{problem_id}/description.md', description)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', hints)

    # Go to contest page on success
    flash('Problem successfully created', 'success')
    logger.info((f"User #{session['user_id']} ({session['username']}) added problem "
                 f"{problem_id} to contest {contest_id}"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@app.route('/contest/<contest_id>/problem/<problem_id>/export', methods=["GET", "POST"])
@admin_required
def export_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    data1 = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(data1) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(data) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        if not contest_ended(data1):
            flash("Are you sure? The contest hasn't ended yet", 'warning')
        return render_template('contest/export_problem.html', data=data[0])

    # Reached via POST

    new_id = contest_id + "-" + problem_id  # this should be safe already

    check = db.execute("SELECT * FROM problems WHERE id=:id", id=new_id)
    if len(check) != 0:
        flash('This problem has already been exported', 'danger')
        return render_template('contest/export_problem.html', data=data[0])

    new_name = data1[0]["name"] + " - " + data[0]["name"]

    # change points value
    if request.form.get("point_value"):
        new_points = request.form.get("point_value")
    else:
        new_points = data[0]["point_value"]

    # Insert into problems databases
    db.execute(("INSERT INTO problems(id, name, point_value, category, flag) "
                "VALUES(:id, :name, :pv, :cat, :flag)"),
               id=new_id, name=new_name, pv=new_points,
               cat=data[0]["category"], flag=data[0]["flag"])

    db.execute("INSERT INTO problem_solved(user_id, problem_id) SELECT user_id, :new_id "
               "FROM contest_solved WHERE contest_id=:cid AND problem_id=:pid",
               new_id=new_id, cid=contest_id, pid=problem_id)

    # Add duplicate submissions (allows rejudging and searching)
    db.execute(("INSERT INTO submissions(date, user_id, problem_id, correct, submitted) "
                "SELECT date, user_id, ?, correct, submitted FROM submissions WHERE "
                "contest_id=? AND problem_id=?"), new_id, contest_id, problem_id)

    # Update global user stats
    db.execute(("UPDATE users SET total_points=total_points+:nv, "
                "problems_solved=problems_solved+1 WHERE id IN (SELECT user_id FROM "
                "contest_solved WHERE contest_id=:cid AND problem_id=:pid)"),
                nv=new_points, cid=contest_id, pid=problem_id)

    os.makedirs(f'metadata/problems/{new_id}')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/description.md',
                f'metadata/problems/{new_id}/description.md')
    shutil.copy(f'metadata/contests/{contest_id}/{problem_id}/hints.md',
                f'metadata/problems/{new_id}/hints.md')
    open(f'metadata/problems/{new_id}/editorial.md', 'w').close()

    logger.info((f"User #{session['user_id']} ({session['username']}) exported problem "
                 f"{problem_id} from contest {contest_id} to {new_id}"),
                extra={"section": "problem"})
    flash('Problem successfully exported', 'success')
    return redirect("/problem/" + new_id)


@app.route('/contest/<contest_id>/problem/<problem_id>/download')
@admin_required
def download_contest_problem(contest_id, problem_id):
    temp_zipfile = BytesIO()
    zf = zipfile.ZipFile(temp_zipfile, 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir(f'metadata/contests/{contest_id}/{problem_id}'):
        zf.write(f'metadata/contests/{contest_id}/{problem_id}/' + file, file)
    if os.path.exists(f'dl/{contest_id}/{problem_id}.zip'):
        zf.write(f'dl/{contest_id}/{problem_id}.zip', f'{problem_id}.zip')
    zf.close()
    temp_zipfile.seek(0)
    return send_file(temp_zipfile, mimetype='zip',
                     download_name=f'{problem_id}.zip', as_attachment=True)


@app.route('/problems')
@login_required
def problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    category = request.args.get("category")
    if not category:
        category = None

    solved_data = db.execute("SELECT problem_id FROM problem_solved WHERE user_id=:uid",
                             uid=session["user_id"])
    solved = set()
    for row in solved_data:
        solved.add(row["problem_id"])

    if category is not None:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE (draft=0 AND category=?)"
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"),
            category, page)
        length = len(db.execute("SELECT * FROM problems WHERE (draft=0 AND category=?)",
                                category))
    else:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE draft=0 "
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"), page)
        length = len(db.execute("SELECT * FROM problems WHERE draft=0"))

    categories = db.execute("SELECT DISTINCT category FROM problems WHERE draft=0")
    categories.sort(key=lambda x: x['category'])

    return render_template('problem/problems.html',
                           data=data, solved=solved, length=-(-length // 50),
                           categories=categories, selected=category)


@app.route("/problems/create", methods=["GET", "POST"])
@admin_required
def create_problem():
    if request.method == "GET":
        return render_template("problem/create.html")

    # Reached via POST

    problem_id = request.form.get("id")
    name = request.form.get("name")
    description = request.form.get("description")
    hints = request.form.get("hints")
    point_value = request.form.get("point_value")
    category = request.form.get("category")
    flag = request.form.get("flag")
    draft = 1 if request.form.get("draft") else 0

    if (not problem_id or not name or not description or not point_value
            or not category or not flag):
        flash('You have not entered all required fields', 'danger')
        return render_template("problem/create.html"), 400

    # Check if problem ID is valid
    if not verify_text(problem_id):
        flash('Invalid problem ID', 'danger')
        return render_template("problem/create.html"), 400

    # Check if flag is valid
    if not verify_flag(flag):
        flash('Invalid flag', 'danger')
        return render_template("problem/create.html"), 400

    description = description.replace('\r', '')
    if not hints:
        hints = ""

    # Ensure problem does not already exist
    problem_info = db.execute("SELECT * FROM problems WHERE id=:problem_id OR name=:name",
                              problem_id=problem_id, name=name)
    if len(problem_info) != 0:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("problem/create.html"), 409

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        filename = problem_id + ".zip"
        file.save("dl/" + filename)
        description += f'\n\n[{filename}](/dl/{filename})'

    # Modify problems table
    db.execute(("INSERT INTO problems (id, name, point_value, category, flag, draft) "
                "VALUES (:id, :name, :point_value, :category, :flag, :draft)"),
               id=problem_id, name=name, point_value=point_value, category=category,
               flag=flag, draft=draft)

    os.makedirs('metadata/problems/' + problem_id)
    write_file('metadata/problems/' + problem_id + '/description.md', description)
    write_file('metadata/problems/' + problem_id + '/hints.md', hints)
    open('metadata/problems/' + problem_id + '/editorial.md', 'w').close()

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"problem {problem_id}"), extra={"section": "problem"})
    flash('Problem successfully created', 'success')
    return redirect("/problem/" + problem_id)


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
    if len(data) != 1 or (data[0]["draft"] == 1 and session["admin"] != 1):
        return render_template("problem/problem_noexist.html"), 404

    data[0]["editorial"] = read_file(f"metadata/problems/{problem_id}/editorial.md")
    data[0]["solved"] = len(
        db.execute("SELECT * FROM problem_solved WHERE user_id=? AND problem_id=?",
                   session["user_id"], problem_id)) == 1
    if request.method == "GET":
        return render_template('problem/problem.html', data=data[0])

    # Reached via POST
    flag = request.form.get("flag")

    if not flag:
        flash('Cannot submit an empty flag', 'danger')
        return render_template('problem/problem.html', data=data[0]), 400

    if not verify_flag(flag):
        flash('Invalid flag', 'danger')
        return render_template('problem/problem.html', data=data[0]), 400

    check = data[0]["flag"] == flag
    db.execute(("INSERT INTO submissions (date, user_id, problem_id, correct, submitted) "
                "VALUES (datetime('now'), :user_id, :problem_id, :check, :flag)"),
               user_id=session["user_id"], problem_id=problem_id, check=check, flag=flag)

    if not check:
        flash('The flag you submitted was incorrect', 'danger')
        return render_template('problem/problem.html', data=data[0])

    # Check if user already solved this problem
    check = db.execute(
        "SELECT * FROM problem_solved WHERE user_id=:uid AND problem_id=:pid",
        uid=session["user_id"], pid=problem_id)
    if len(check) == 0:
        db.execute("INSERT INTO problem_solved(user_id, problem_id) VALUES(:uid, :pid)",
                   uid=session["user_id"], pid=problem_id)

        # Update total points and problems solved
        db.execute(("UPDATE users SET total_points=total_points+:pv, "
                    "problems_solved=problems_solved+1 WHERE id=:uid"),
                   pv=data[0]["point_value"], uid=session["user_id"])

    data[0]["solved"] = True
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

    logger.info(f"User #{session['user_id']} ({session['username']}) published {problem_id}",  # noqa
                extra={"section": "problem"})
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

    if data[0]["draft"] == 1 and session["admin"] != 1:
        return render_template("problem/problem_noexist.html"), 404

    return render_template('problem/problemeditorial.html', data=data[0])


@app.route('/problem/<problem_id>/edit', methods=["GET", "POST"])
@admin_required
def editproblem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    if request.method == "GET":
        return render_template('problem/edit_problem.html', data=data[0])

    # Reached via POST

    new_name = request.form.get("name")
    new_description = request.form.get("description")
    new_hint = request.form.get("hints")
    new_category = request.form.get("category")
    new_points = int(request.form.get("point_value"))
    new_flag = request.form.get("flag")

    if not new_name or not new_description or not new_category or not new_points:
        flash('You have not entered all required fields', 'danger')
        return render_template('problem/edit_problem.html', data=data[0]), 400

    if new_flag:
        if not verify_flag(new_flag):
            flash('Invalid flag', 'danger')
            return render_template('problem/edit_problem.html', data=data[0]), 400
        if request.form.get("rejudge"):
            db.execute("UPDATE submissions SET correct=0 WHERE problem_id=:pid",
                       pid=problem_id)
            db.execute(
                ("UPDATE users SET total_points=total_points-:pv, "
                 "problems_solved=problems_solved-1 WHERE id IN "
                 "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
                 pv=data[0]["point_value"], pid=problem_id
            )
            db.execute("DELETE FROM problem_solved WHERE problem_id=:pid", pid=problem_id)
            db.execute(("UPDATE submissions SET correct=1 WHERE "
                        "problem_id=:pid AND submitted=:flag"),
                       pid=problem_id, flag=new_flag)
            db.execute(("INSERT INTO problem_solved (user_id, problem_id) "
                        "SELECT DISTINCT user_id, problem_id FROM submissions WHERE "
                        "problem_id=:pid AND correct=1"), pid=problem_id)
            db.execute(
                ("UPDATE users SET total_points=total_points+:pv, "
                 "problems_solved=problems_solved+1 WHERE id IN "
                 "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
                 pv=data[0]["point_value"], pid=problem_id
            )
    else:
        new_flag = data[0]["flag"]

    new_description = new_description.replace('\r', '')
    if not new_hint:
        new_hint = ""

    db.execute(("UPDATE problems SET name=:name, category=:category, point_value=:pv, "
                "flag=:flag WHERE id=:problem_id"),
               name=new_name, category=new_category, pv=new_points,
               problem_id=problem_id, flag=new_flag)
    db.execute(
        ("UPDATE users SET total_points=total_points+:dpv WHERE id IN "
         "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
         dpv=new_points - data[0]["point_value"], pid=problem_id
    )
    write_file('metadata/problems/' + problem_id + '/description.md', new_description)
    write_file('metadata/problems/' + problem_id + '/hints.md', new_hint)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated problem "
                 f"{problem_id}"), extra={"section": "problem"})
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
        return render_template('problem/edit_editorial.html', data=data[0])

    # Reached via POST

    new_editorial = request.form.get("editorial")
    if not new_editorial:
        new_editorial = ""
    new_editorial = new_editorial.replace('\r', '')

    write_file('metadata/problems/' + problem_id + '/editorial.md', new_editorial)

    logger.info((f"User #{session['user_id']} ({session['username']}) updated the "
                 f"editorial for problem {problem_id}"), extra={"section": "problem"})
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
    db.execute(
        ("UPDATE users SET total_points=total_points-:pv, "
         "problems_solved=problems_solved-1 WHERE id IN "
         "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
         pv=data[0]["point_value"], pid=problem_id
    )
    db.execute("DELETE FROM problem_solved WHERE problem_id=:pid", pid=problem_id)
    db.execute("COMMIT")
    shutil.rmtree(f"metadata/problems/{problem_id}")

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"problem {problem_id}"), extra={"section": "problem"})
    flash('Problem successfully deleted', 'success')
    return redirect("/problems")


@app.route('/problem/<problem_id>/download')
@admin_required
def download_problem(problem_id):
    temp_zipfile = BytesIO()
    zf = zipfile.ZipFile(temp_zipfile, 'w', zipfile.ZIP_DEFLATED)
    for file in os.listdir(f'metadata/problems/{problem_id}'):
        zf.write(f'metadata/problems/{problem_id}/' + file, file)
    if os.path.exists(f'dl/{problem_id}.zip'):
        zf.write(f'dl/{problem_id}.zip', f'{problem_id}.zip')
    zf.close()
    temp_zipfile.seek(0)
    return send_file(temp_zipfile, mimetype='zip',
                     download_name=f'{problem_id}.zip', as_attachment=True)


@app.route("/admin/console")
@admin_required
def admin_console():
    return render_template("admin/console.html", ver="v3.2.2",
                           maintenance_mode=os.path.exists('maintenance_mode'))


@app.route("/admin/submissions")
@admin_required
def admin_submissions():
    submissions = None

    modifier = " WHERE"
    args = []

    if request.args.get("username"):
        modifier += " username=? AND"
        args.append(request.args.get("username"))

    if request.args.get("problem_id"):
        modifier += " problem_id=? AND"
        args.append(request.args.get("problem_id"))

    if request.args.get("contest_id"):
        if request.args.get("contest_id") == "None":
            modifier += " contest_id IS NULL AND"
        else:
            modifier += " contest_id=? AND"
            args.append(request.args.get("contest_id"))

    if request.args.get("correct"):
        modifier += " correct=? AND"
        args.append(request.args.get("correct") == "AC")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50
    modifier += " 1=1"

    length = len(db.execute(("SELECT submissions.*, users.username FROM submissions "
                             "LEFT JOIN users ON user_id=users.id") + modifier, *args))

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

    msg = "unbanned" if user["banned"] else "banned"
    flash(f"Successfully {msg} {user['username']}", "success")
    logger.info((f"User #{user_id} ({user['username']}) {msg} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "auth"})
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

    if user[0]["id"] == 1:
        flash(("Cannot reset the super-admin password. "
               "Use the forgot password page instead."), "danger")
        return redirect("/admin/users")

    password = generate_password()
    db.execute("UPDATE users SET password=:p WHERE id=:id",
               p=generate_password_hash(password), id=user_id)

    flash(f"Password for {user[0]['username']} was reset! Their new password is {password}",  # noqa
          "success")
    logger.info((f"User #{user_id} ({user[0]['username']})'s password reset by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "auth"})
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
        logger.info(f"Admin privileges for user #{user_id} ({user[0]['username']}) revoked",  # noqa
                    extra={"section": "auth"})
        return redirect("/admin/users")
    else:
        db.execute("UPDATE users SET admin=1 WHERE id=:id", id=user_id)
        flash("Admin privileges for " + user[0]["username"] + " granted", "success")
        logger.info((f"Admin privileges for user #{user_id} ({user[0]['username']}) "
                     f"granted by user #{session['user_id']} ({session['username']})"),
                    extra={"section": "auth"})
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

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"announcement {aid}"), extra={"section": "announcement"})
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

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"announcement {aid}"), extra={"section": "announcement"})
    flash('Announcement successfully deleted', 'success')
    return redirect("/")


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

    logger.info((f"User #{session['user_id']} ({session['username']}) updated "
                 f"announcement {aid}"), extra={"section": "announcement"})
    flash('Announcement successfully edited', 'success')
    return redirect("/")


@app.route("/admin/maintenance", methods=["POST"])
@admin_required
def maintenance():
    maintenance_mode = os.path.exists('maintenance_mode')

    msg = "Disabled" if maintenance_mode else "Enabled"
    if maintenance_mode:
        os.remove('maintenance_mode')
    else:
        write_file('maintenance_mode', '')
    flash(msg + " maintenance mode", "success")

    logger.info((f"{msg} maintenance mode by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "misc"})
    return redirect('/admin/console')


@app.route("/admin/edithomepage", methods=["GET", "POST"])
@admin_required
def edit_homepage():
    if request.method == "GET":
        return render_template("admin/edithomepage.html")

    # Reached via POST

    layout_method = request.form.get("method")
    content = request.form.get("content")

    if not content:
        flash('You have not entered all required fields', 'danger')
        return render_template("admin/edithomepage.html"), 400
    if not layout_method or layout_method not in ["1", "2"]:
        layout_method = "1"

    content = layout_method + "\n" + content.replace('\r', '')

    write_file(app.config['HOMEPAGE_FILE'], content)

    logger.info(f"User #{session['user_id']} ({session['username']}) updated the homepage ",  # noqa
                extra={"section": "announcement"})
    flash("You have successfully edited the homepage!", "success")
    return redirect("/admin/previewhomepage")


@app.route("/admin/previewhomepage")
@admin_required
def preview_homepage():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 10

    data = db.execute(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
    length = len(db.execute("SELECT * FROM announcements"))

    template_type = read_file(app.config['HOMEPAGE_FILE'])[0]
    return render_template(f"home_fragment/home{template_type}.html",
                           data=data,
                           length=-(-length // 10))


@app.route("/users/<username>/profile")
@login_required
def profile(username):
    user_info = db.execute("SELECT * FROM users WHERE username=:username", username=username)
    if len(user_info) == 0:
        return render_template("error/404.html"), 404
    return render_template("profile/profile.html", user_data=user_info[0])


@app.route("/ranking")
@login_required
def ranking():
    user_info = db.execute("SELECT * FROM users WHERE verified=1 ORDER BY total_points DESC")
    return render_template("ranking.html", user_data=user_info)


# Error handling
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    if request.path.startswith('/api/'):
        return json_fail(e.description, e.code)
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


if __name__ == "__main__":
    app.run(debug=True, port=5000)
