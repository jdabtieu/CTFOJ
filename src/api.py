from flask import Blueprint, redirect
import uuid
import logging

from helpers import *  # noqa

api = Blueprint("api", __name__)

logger = logging.getLogger("CTFOJ")


@api.route("/")
def api_documentation():
    return redirect("https://github.com/jdabtieu/CTFOJ/wiki/CTFOJ-API")


@api.route("/getkey", methods=["POST"])
@login_required
def get_api_key():
    logger.info((f"User #{session['user_id']} ({session['username']}) "
                 "generated a new API key"), extra={"section": "api"})
    from application import db
    new_key = str(uuid.uuid4())
    db.execute("UPDATE users SET api=? WHERE id=?", new_key, session["user_id"])
    return new_key


@api.route("/problem")
@api_login_required
def problem():
    if "id" not in request.args:
        return json_fail("Must provide problem ID", 400)
    problem_id = request.args["id"]

    from application import db
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not api_admin()):
        return json_fail("Problem not found", 404)

    description = read_file(f"metadata/problems/{problem_id}/description.md")
    hints = read_file(f"metadata/problems/{problem_id}/hints.md")
    editorial = read_file(f"metadata/problems/{problem_id}/editorial.md")

    returns = {
        "description": description,
        "hints": hints,
        "editorial": editorial,
    }
    return json_success(returns)


@api.route("/contest/problem")
@api_login_required
def contest_problem():
    if "cid" not in request.args:
        return json_fail("Must provide contest ID", 400)
    if "pid" not in request.args:
        return json_fail("Must provide problem ID", 400)
    contest_id = request.args["cid"]
    problem_id = request.args["pid"]

    from application import db
    contest = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if len(contest) != 1:
        return json_fail("Contest not found", 404)
    start = datetime.strptime(contest[0]["start"], "%Y-%m-%d %H:%M:%S")
    if datetime.utcnow() < start and not api_admin():
        return json_fail("The contest has not started", 403)
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not api_admin()):
        return json_fail("Problem not found", 404)

    description = read_file(f"metadata/contests/{contest_id}/{problem_id}/description.md")
    hints = read_file(f"metadata/contests/{contest_id}/{problem_id}/hints.md")

    returns = {
        "description": description,
        "hints": hints,
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)


@api.route("/contests")
@api_login_required
def contests():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    ids = request.args["id"].split(",")
    from application import db
    res = db.execute("SELECT * FROM contests WHERE id IN (?)", ids)
    returns = {}
    for item in res:
        returns[item["id"]] = read_file(f"metadata/contests/{item['id']}/description.md")
    return json_success(returns)


@api.route("/announcements")
def announcement():
    from application import app
    if app.config["USE_HOMEPAGE"] and read_file(app.config['HOMEPAGE_FILE'])[0] == '2':
        return _announcement()
    elif not api_logged_in():
        return json_fail("Unauthorized", 401)
    return _announcement()


def _announcement():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    nums = [int(e) for e in request.args["id"].split(",") if e.isdigit()][:10]
    from application import db
    res = db.execute("SELECT * FROM announcements WHERE id IN (?)", nums)
    returns = {}
    for item in res:
        returns[item["id"]] = read_file(f"metadata/announcements/{item['id']}.md")
    return json_success(returns)


@api.route("/homepage")
def homepage():
    from application import app
    if app.config["USE_HOMEPAGE"]:
        return _homepage()
    elif not api_admin():
        return json_fail("Unauthorized", 401)
    return _homepage()


def _homepage():
    from application import app
    return json_success({"data": read_file(app.config['HOMEPAGE_FILE'])[2:]})
