import logging
import os
import requests
import sys
import uuid
from datetime import datetime, timedelta

import jwt
from flask import (abort, Flask, flash, redirect, render_template, request,
                   send_from_directory, session)
from flask_mail import Mail
from flask_session import Session
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException, InternalServerError, default_exceptions
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import *  # noqa
from db import db
from middlewares import ProxyFix

app = Flask(__name__)

try:
    app.config.from_object('settings')
except Exception as e:
    sys.stderr.write(str(e))
    app.config.from_object('default_settings')
app.jinja_env.globals['CLUB_NAME'] = app.config['CLUB_NAME']
app.jinja_env.globals['USE_CAPTCHA'] = app.config['USE_CAPTCHA']
app.jinja_env.globals.update(check_perm=check_perm)

# Add middlewares
if app.config["USE_X_FORWARDED_FOR"]:
    app.wsgi_app = ProxyFix(app.wsgi_app)


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

# Configure flask-mail
mail = Mail(app)

# Configure flask-WTF
csrf = CSRFProtect(app)
csrf.init_app(app)

# Load API
from views.api import api as view_api  # noqa
from views.contest import api as view_contest  # noqa
from views.problem import api as view_problem  # noqa
from views.admin import api as view_admin  # noqa
app.register_blueprint(view_api, url_prefix="/api")
app.register_blueprint(view_contest, url_prefix="/contest")
app.register_blueprint(view_problem, url_prefix="/problem")
app.register_blueprint(view_admin, url_prefix="/admin")

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


def check_for_maintenance():
    """
    Pre-request handler to block requests during maintenance mode
    """
    # Don't prevent login or getting assets
    if request.path == '/login' or request.path.startswith('/assets/'):
        return

    maintenance_mode = bool(os.path.exists('maintenance_mode'))
    if maintenance_mode:
        if request.path.startswith('/api/'):
            if not check_perm(["ADMIN", "SUPERADMIN"], api_get_perms()):
                return json_fail("The site is currently undergoing maintenance", 503)
            else:
                return

        if not check_perm(["ADMIN", "SUPERADMIN"]):
            with open('maintenance_mode', 'r') as f:
                msg = f.read()
            return render_template("error/maintenance.html", msg=msg), 503
        else:
            flash("Maintenance mode is enabled", "maintenance")


def refresh_perms():
    """
    Pre-request handler to ensure permission freshness
    """
    if not session.get("user_id"):
        return
    if "perms_expiry" not in session:  # Old, invalid session
        session.clear()
        return redirect("/login")
    safer_methods = ["GET", "HEAD"]
    if request.method not in safer_methods or (request.method in safer_methods and session["perms_expiry"] < datetime.now()):
        perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", session["user_id"])
        session["perms"] = set([x["perm_id"] for x in perms])
        session["perms_expiry"] = datetime.now() + timedelta(seconds=300)
    return


@app.before_request
def before_hooks():
    funcs = [check_for_maintenance, refresh_perms]
    for f in funcs:
        r = f()
        if r:
            return r


@app.route("/")
def index():
    if session.get('username'):
        return logged_in_homepage()

    # Redirect to login page if homepage setting disabled
    if not app.config["USE_HOMEPAGE"]:
        return redirect("/login")

    template = read_file(app.config['HOMEPAGE_FILE'])
    template_type = int(template[0])
    props = {"homepage": read_file(app.config['HOMEPAGE_FILE'])[2:]}
    if template_type == 2:
        page = request.args.get("page") or "1"
        page = (int(page) - 1) * 10

        props["data"] = db.execute(
            "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
        props["length"] = db.execute(
            "SELECT COUNT(*) AS cnt FROM announcements")[0]["cnt"]
    return render_template(f"home_fragment/home{template_type}.html", props=props)


def logged_in_homepage():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 10

    data = db.execute(
        "SELECT * FROM announcements ORDER BY id DESC LIMIT 10 OFFSET ?", page)
    length = db.execute("SELECT COUNT(*) AS cnt FROM announcements")[0]["cnt"]

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


@app.route("/dl/<problem_id>.zip")
@login_required
def dl_file(problem_id):
    problem = db.execute("SELECT * FROM problems WHERE id=?", problem_id)
    if len(problem) == 0 or (problem[0]["status"] == PROBLEM_STAT["DRAFT"] and not
                             check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])):
        return abort(404)
    return send_from_directory("dl/", f"{problem_id}.zip", as_attachment=True)


@app.route("/dl/<contest_id>/<problem_id>.zip")
@login_required
def dl_contest(contest_id, problem_id):
    from views.contest import _get_contest, _get_problem
    _, err = _get_contest(contest_id)
    if err:
        return abort(404)
    _, err = _get_problem(contest_id, problem_id)
    if err:
        return abort(404)
    return send_from_directory("dl/", f"{contest_id}/{problem_id}.zip",
                               as_attachment=True)


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
    if code:
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

    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", rows[0]["id"])

    # Remember which user has logged in
    session["user_id"] = rows[0]["id"]
    session["username"] = rows[0]["username"]
    session["perms"] = set([x["perm_id"] for x in perms])
    session["perms_expiry"] = datetime.now() + timedelta(seconds=300)

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
    email = request.form.get("email")

    code = register_chk(username, password, email)
    if code:
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), code
    email = email.lower()

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/register.html",
                                   site_key=app.config['HCAPTCHA_SITE']), 400

    # Create entry & check for duplicate
    try:
        db.execute(("INSERT INTO users(username, password, email, join_date) "
                    "VALUES(?, ?, ?, datetime('now'))"),
                   username, generate_password_hash(password), email)
    except ValueError:
        if db.execute("SELECT COUNT(*) AS cnt FROM users WHERE username=?", username)[0]["cnt"] > 0:
            flash('Username already in use', 'danger')
        elif db.execute("SELECT COUNT(*) AS cnt FROM users WHERE email=?", email)[0]["cnt"] > 0:
            flash('Email already in use', 'danger')
        return render_template("auth/register.html",
                               site_key=app.config['HCAPTCHA_SITE']), 400

    if not app.config['TESTING']:
        token = create_jwt({'email': email}, app.config['SECRET_KEY'])
        text = render_template('email/confirm_account.html',
                               username=username, token=token)
        send_email('CTFOJ Account Confirmation',
                   app.config['MAIL_DEFAULT_SENDER'], [email], text)

    logger.info((f"User {username} ({email}) has initiated a registration request "
                 f"on IP {request.remote_addr}"), extra={"section": "auth"})
    token = create_jwt({'username': username}, app.config['SECRET_KEY'])
    return render_template("auth/register_interstitial.html", token=token)


@app.route("/auth/resend_registration_confirmation", methods=["POST"])
def resend_registration_confirmation():
    try:
        token = jwt.decode(request.form.get("token"), app.config['SECRET_KEY'], algorithms=['HS256'])
    except Exception:
        return "Invalid token. Please contact an admin.", 400
    if datetime.strptime(token["expiration"], "%Y-%m-%dT%H:%M:%S.%f") < datetime.utcnow():
        return "Page expired. Please contact an admin.", 400
    username = token["username"]
    user = db.execute("SELECT * FROM users WHERE username=?", username)
    if len(user) == 0:
        return "User doesn't exist.", 400
    if user[0]["verified"]:
        return "/login", 302
    if user[0]['registration_resend_attempts'] >= 2:  # allow 2 tries
        return "You have tried too many times. Please contact an admin.", 400
    if not app.config['TESTING']:
        token = create_jwt({'email': user[0]["email"]}, app.config['SECRET_KEY'])
        text = render_template('email/confirm_account.html',
                               username=username, token=token)
        send_email('CTFOJ Account Confirmation',
                   app.config['MAIL_DEFAULT_SENDER'], [user[0]["email"]], text)
    db.execute("UPDATE users SET registration_resend_attempts=registration_resend_attempts+1 WHERE username=?", username)
    return "OK"


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

    r = db.execute("UPDATE users SET verified=1 WHERE email=? AND verified=0", token['email'])
    if r == 0:
        flash("Email verification link invalid", "danger")
        return redirect("/register")

    # Log user in
    user = db.execute(
        "SELECT * FROM users WHERE email=?", token['email'])[0]
    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user["id"])
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["perms"] = set([x["perm_id"] for x in perms])
    session["perms_expiry"] = datetime.now() + timedelta(seconds=300)

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
    r = db.execute("DELETE FROM users WHERE verified=0 and email=?", token['email'])
    if r == 0:
        flash("Email verification link invalid", "danger")
        return redirect("/register")

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
    user = db.execute("SELECT * FROM users WHERE email=:email", email=token['email'])[0]
    perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user["id"])

    # Remember which user has logged in
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["perms"] = set([x["perm_id"] for x in perms])
    session["perms_expiry"] = datetime.now() + timedelta(seconds=300)

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
        return render_template("auth/change_password.html")

    # Reached using POST

    old_password = request.form.get("password")
    new_password = request.form.get("newPassword")
    confirmation = request.form.get("confirmation")

    # Ensure passwords were submitted and they match
    if not old_password:
        flash('Password cannot be blank', 'danger')
        return render_template("auth/change_password.html"), 400
    if not new_password or len(new_password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/change_password.html"), 400
    if not confirmation or new_password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/change_password.html"), 400

    # Ensure username exists and password is correct
    rows = db.execute("SELECT * FROM users WHERE id=:id", id=session["user_id"])
    if len(rows) != 1 or not check_password_hash(rows[0]["password"], old_password):
        flash('Incorrect password', 'danger')
        return render_template("auth/change_password.html"), 401

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
        return render_template("auth/forgot_password.html",
                               site_key=app.config['HCAPTCHA_SITE'])

    # Reached via POST

    email = request.form.get("email")
    if not email:
        flash('Email cannot be blank', 'danger')
        return render_template("auth/forgot_password.html"), 400

    # Ensure captcha is valid
    if app.config['USE_CAPTCHA']:
        if not check_captcha(app.config['HCAPTCHA_SECRET'],
                             request.form.get('h-captcha-response'),
                             app.config['HCAPTCHA_SITE']):
            return render_template("auth/forgot_password.html",
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
    return render_template("auth/forgot_password.html")


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
        return render_template('auth/reset_password.html')

    password = request.form.get("password")
    confirmation = request.form.get("confirmation")

    if not password or len(password) < 8:
        flash('New password must be at least 8 characters', 'danger')
        return render_template("auth/reset_password.html"), 400
    if not confirmation or password != confirmation:
        flash('Passwords do not match', 'danger')
        return render_template("auth/reset_password.html"), 400

    db.execute("UPDATE users SET password=:new WHERE id=:id",
               new=generate_password_hash(password), id=user_id)

    logger.info((f"User #{user_id} completed a password reset from "
                 f"IP {request.remote_addr}"), extra={"section": "auth"})
    flash('Your password has been successfully reset', 'success')
    return redirect("/login")


@app.route("/contests")
def contests():
    past = db.execute(
        "SELECT * FROM contests WHERE end < datetime('now') ORDER BY end DESC")
    current = db.execute(
        ("SELECT * FROM contests WHERE end > datetime('now') AND "
         "start <= datetime('now') ORDER BY end DESC"))
    future = db.execute(
        "SELECT * FROM contests WHERE start > datetime('now') ORDER BY start DESC")
    return render_template("contest/list.html",
                           past=past, current=current, future=future)


@app.route("/contests/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def create_contest():
    if request.method == "GET":
        return render_template("contest/create.html")

    # Reached using POST

    contest_id = request.form.get("contest_id")
    start = request.form.get("start")
    end = request.form.get("end")
    description = request.form.get("description").replace('\r', '').strip()
    contest_name = request.form.get("contest_name")
    scoreboard_key = str(uuid.uuid4())
    scoreboard_visible = bool(request.form.get("scoreboard_visible"))

    # Ensure contest ID is valid
    if not contest_id or not verify_text(contest_id) or contest_id == "None":
        flash('Invalid contest ID', 'danger')
        return render_template("contest/create.html"), 400

    # Ensure start and end dates are valid
    check_start = datetime.strptime(start, "%Y-%m-%dT%H:%M:%S.%fZ")
    check_end = datetime.strptime(end, "%Y-%m-%dT%H:%M:%S.%fZ")
    if check_end < check_start:
        flash('Contest cannot end before it starts!', 'danger')
        return render_template("contest/create.html"), 400

    # Ensure the description exists
    if not description:
        flash('Description cannot be empty', 'danger')
        return render_template("contest/create.html"), 400

    # Create & ensure contest ID doesn't already exist
    try:
        db.execute(
            ("INSERT INTO contests (id, name, start, end, scoreboard_visible, scoreboard_key)"
             " VALUES (?, ?, datetime(?), datetime(?), ?, ?)"),
            contest_id, contest_name, start, end, scoreboard_visible, scoreboard_key)
    except ValueError:
        flash('A contest with that ID already exists', 'danger')
        return render_template("contest/create.html"), 400

    os.makedirs('metadata/contests/' + contest_id)
    write_file('metadata/contests/' + contest_id + '/description.md', description)

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully created', 'success')
    return redirect("/contest/" + contest_id)


@app.route('/problems')
def problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    category = request.args.get("category")
    if not category:
        category = None

    solved = set()
    if session.get("user_id"):
        solved_db = db.execute("SELECT problem_id FROM problem_solved WHERE user_id=:uid",
                               uid=session["user_id"])
        for row in solved_db:
            solved.add(row["problem_id"])

    if category is not None:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE (status=0 AND category=?)"
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"),
            category, page)
        length = db.execute(("SELECT COUNT(*) AS cnt FROM problems WHERE "
                             "status=0 AND category=?"), category)[0]["cnt"]
    else:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE status=0 "
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"), page)
        length = db.execute("SELECT COUNT(*) AS cnt FROM problems WHERE status=0")[0]["cnt"]  # noqa E501

    categories = db.execute("SELECT DISTINCT category FROM problems WHERE status=0")
    categories.sort(key=lambda x: x['category'])

    is_ongoing_contest = len(db.execute(
        "SELECT * FROM contests WHERE end > datetime('now') AND start <= datetime('now')"
    ))

    return render_template('problem/list.html',
                           data=data, solved=solved, length=-(-length // 50),
                           categories=categories, selected=category,
                           is_ongoing_contest=is_ongoing_contest)


@app.route('/problems/archived')
def archived_problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    category = request.args.get("category")
    if not category:
        category = None

    solved = set()
    if session.get("user_id"):
        solved_db = db.execute("SELECT problem_id FROM problem_solved WHERE user_id=:uid",
                               uid=session["user_id"])
        for row in solved_db:
            solved.add(row["problem_id"])

    if category is not None:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE (status=2 AND category=?)"
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"),
            category, page)
        length = db.execute(("SELECT COUNT(*) AS cnt FROM problems WHERE "
                             "status=0 AND category=?"), category)[0]["cnt"]
    else:
        data = db.execute(
            ("SELECT problems.*, COUNT(DISTINCT problem_solved.user_id) AS sols "
             "FROM problems LEFT JOIN problem_solved ON "
             "problems.id=problem_solved.problem_id WHERE status=2 "
             "GROUP BY problems.id ORDER BY id ASC LIMIT 50 OFFSET ?"), page)
        length = db.execute("SELECT COUNT(*) AS cnt FROM problems WHERE status=2")[0]["cnt"]  # noqa E501

    categories = db.execute("SELECT DISTINCT category FROM problems WHERE status=2")
    categories.sort(key=lambda x: x['category'])

    return render_template('problem/list_archived.html',
                           data=data, solved=solved, length=-(-length // 50),
                           categories=categories, selected=category)


@app.route("/problems/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
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
    flag_hint = request.form.get("flag_hint")
    if not flag_hint:
        flag_hint = ""
    instanced = bool(request.form.get("instanced"))

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

    # Create & ensure problem doesn't already exist
    try:
        db.execute(("INSERT INTO problems (id, name, point_value, category, flag, "
                    "status, flag_hint, instanced) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"),
                   problem_id, name, point_value, category, flag, draft, flag_hint,
                   instanced)
    except ValueError:
        flash('A problem with this name or ID already exists', 'danger')
        return render_template("problem/create.html"), 400

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        filename = problem_id + ".zip"
        file.save("dl/" + filename)
        description += f'\n\n[{filename}](/dl/{filename})'

    os.makedirs('metadata/problems/' + problem_id)
    write_file('metadata/problems/' + problem_id + '/description.md', description)
    write_file('metadata/problems/' + problem_id + '/hints.md', hints)
    open('metadata/problems/' + problem_id + '/editorial.md', 'w').close()

    logger.info((f"User #{session['user_id']} ({session['username']}) created "
                 f"problem {problem_id}"), extra={"section": "problem"})
    flash('Problem successfully created', 'success')
    return redirect("/problem/" + problem_id)


@app.route('/problems/draft')
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def draft_problems():
    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    data = db.execute("SELECT * FROM problems WHERE status=1 LIMIT 50 OFFSET ?", page)
    length = db.execute("SELECT COUNT(*) AS cnt FROM problems WHERE status=1")[0]["cnt"]

    return render_template('problem/list_draft.html',
                           data=data, length=-(-length // 50))


@app.route("/users/<username>/profile")
@login_required
def profile(username):
    user_info = db.execute("SELECT * FROM users WHERE username=:username", username=username)
    if len(user_info) == 0:
        return render_template("error/404.html"), 404
    return render_template("profile/profile.html", user_data=user_info[0])


@app.route("/ranking")
def ranking():
    user_info = db.execute("SELECT * FROM users WHERE verified=1 ORDER BY total_points DESC")

    is_ongoing_contest = len(db.execute(
        "SELECT * FROM contests WHERE end > datetime('now') AND start <= datetime('now')"
    ))

    return render_template("ranking.html", user_data=user_info,
                           is_ongoing_contest=is_ongoing_contest)


# Error handling
def errorhandler(e):
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    if request.path.startswith('/api/'):
        if e.code == 500:
            return json_fail("Internal Server Error", 500)
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
    return response


if __name__ == "__main__":
    app.run(debug=True, port=5000)
