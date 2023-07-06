from flask import Blueprint, redirect, current_app as app
import uuid
import logging

from helpers import *  # noqa
from application import db

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
    new_key = str(uuid.uuid4())
    db.execute("UPDATE users SET api=? WHERE id=?", new_key, session["user_id"])
    return new_key


@api.route("/problem")
@api_login_required
def problem():
    if "id" not in request.args:
        return json_fail("Must provide problem ID", 400)
    problem_id = request.args["id"]

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
        "flag_hint": data[0]["flag_hint"],
    }
    return json_success(returns)


@api.route("/instancer/query")
@api_login_required
def query_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
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
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not api_admin()):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/query",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)


@api.route("/instancer/create")
@api_login_required
def create_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
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
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not api_admin()):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
        "flag": data[0]["flag"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/create",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)


@api.route("/instancer/destroy")
@api_login_required
def destroy_instancer():
    if "id" not in request.args:
        return json_fail("Must provide instancer ID", 400)

    # Check perms
    key = request.args["id"].split("/", 1)
    contest_id = key[0] if len(key) == 2 else None
    problem_id = key[-1]

    if contest_id:
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
    else:
        data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
        if len(data) == 0 or (data[0]["draft"] and not api_admin()):
            return json_fail("Problem not found", 404)

    body = {
        "name": request.args["id"],
        "player": session["user_id"],
    }

    headers = {
        "Authorization": "Bearer " + app.config["INSTANCER_TOKEN"],
    }

    try:
        response = requests.post(app.config["INSTANCER_HOST"] + "/api/v1/destroy",
                                 headers=headers, json=body)
        return json_success(response.json())
    except Exception:
        return json_fail("Failed to get a valid response from the instance server", 500)


@api.route("/contest/problem")
@api_login_required
def contest_problem():
    if "cid" not in request.args:
        return json_fail("Must provide contest ID", 400)
    if "pid" not in request.args:
        return json_fail("Must provide problem ID", 400)
    contest_id = request.args["cid"]
    problem_id = request.args["pid"]

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


@api.route("/contest/scoreboard/<contest_id>")
def contest_scoreboard(contest_id):
    if not request.args.get("key"):
        return json_fail("Unauthorized", 401)

    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return json_fail("The contest doesn't exist", 404)

    # Ensure proper permissions
    if request.args.get("key") != contest_info[0]["scoreboard_key"]:
        return json_fail('Invalid token', 401)

    data = db.execute(
        ("SELECT user_id, points, lastAC, username FROM contest_users "
         "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
         "hidden=0 ORDER BY points DESC, lastAC ASC"),
        cid=contest_id)
    teams = db.execute("SELECT id, username FROM users")
    teams = {x["id"]: x["username"] for x in teams}
    ret = {"standings": []}
    for i in range(len(data)):
        ret["standings"].append({
            "pos": i + 1,
            "team": teams[data[i]["user_id"]],
            "score": data[i]["points"],
        })

    return json.dumps(ret)


@api.route("/contests")
@api_login_required
def contests():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    ids = request.args["id"].split(",")
    res = db.execute("SELECT * FROM contests WHERE id IN (?)", ids)
    returns = {}
    for item in res:
        returns[item["id"]] = read_file(f"metadata/contests/{item['id']}/description.md")
    return json_success(returns)


@api.route("/announcements")
def announcement():
    if app.config["USE_HOMEPAGE"] and read_file(app.config['HOMEPAGE_FILE'])[0] == '2':
        return _announcement()
    elif not api_logged_in():
        return json_fail("Unauthorized", 401)
    return _announcement()


def _announcement():
    if "id" not in request.args:
        return json_fail("Must specify ids", 400)
    nums = [int(e) for e in request.args["id"].split(",") if e.isdigit()][:10]
    res = db.execute("SELECT * FROM announcements WHERE id IN (?)", nums)
    returns = {}
    for item in res:
        returns[item["id"]] = read_file(f"metadata/announcements/{item['id']}.md")
    return json_success(returns)


@api.route("/homepage")
def homepage():
    if app.config["USE_HOMEPAGE"]:
        return _homepage()
    elif not api_admin():
        return json_fail("Unauthorized", 401)
    return _homepage()


def _homepage():
    return json_success({"data": read_file(app.config['HOMEPAGE_FILE'])[2:]})
