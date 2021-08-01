from flask import Blueprint, make_response, send_from_directory, redirect

from helpers import *  # noqa

api = Blueprint("api", __name__)


@api.route("/")
def api_documentation():
    return redirect("https://github.com/jdabtieu/CTFOJ/wiki/CTFOJ-API")


@api.route("/problem/description/<problem_id>")
@api_login_required
def problem_description(problem_id):
    from application import db
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not session["admin"]):
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "description.md")


@api.route("/problem/hints/<problem_id>")
@api_login_required
def problem_hint(problem_id):
    from application import db
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not session["admin"]):
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "hints.md")


@api.route("/problem/editorial/<problem_id>")
@api_login_required
def problem_editorial(problem_id):
    from application import db
    data = db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not session["admin"]):
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "editorial.md")


@api.route("/contest/<contest_id>/problem/description/<problem_id>")
@api_login_required
def contest_problem_description(contest_id, problem_id):
    from application import db
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not session["admin"]):
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/contests/{contest_id}/{problem_id}",
                               "description.md")


@api.route("/contest/<contest_id>/problem/hints/<problem_id>")
@api_login_required
def contest_problem_hint(contest_id, problem_id):
    from application import db
    data = db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)
    if len(data) == 0 or (data[0]["draft"] and not session["admin"]):
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/contests/{contest_id}/{problem_id}",
                               "hints.md")


@api.route("/contest/<contest_id>")
@api_login_required
def contest_description(contest_id):
    from application import db
    if len(db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)) == 0:
        return make_response(("Contest not found", 404))
    return send_from_directory(f"metadata/contests/{contest_id}", "description.md")


@api.route("/announcement/<announcement_id>")
def announcement(announcement_id):
    from application import app
    if not session or 'username' not in session:  # not logged in
        if (not app.config["USE_HOMEPAGE"]
                or (read_file('templates/unauth_index.html')[0] != '2')):
            return make_response(("Unauthorized", 401))
    from application import db
    if len(db.execute(
            "SELECT * FROM announcements WHERE id=:aid", aid=announcement_id)) == 0:
        return make_response(("Announcement not found", 404))
    return send_from_directory("metadata/announcements", f"{announcement_id}.md")


@api.route("/homepage")
def homepage():
    from application import app
    if not app.config["USE_HOMEPAGE"] and not session["admin"]:
        return make_response(("Unauthorized", 403))
    return read_file(app.config['HOMEPAGE_FILE'])[2:]
