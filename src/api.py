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
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "description.md")


@api.route("/problem/hints/<problem_id>")
@api_login_required
def problem_hint(problem_id):
    from application import db
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "hints.md")


@api.route("/problem/editorial/<problem_id>")
@api_login_required
def problem_editorial(problem_id):
    from application import db
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "editorial.md")


@api.route("/contest/<contest_id>/problem/description/<problem_id>")
@api_login_required
def contest_problem_description(contest_id, problem_id):
    from application import db
    if len(db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/contests/{contest_id}/{problem_id}",
                               "description.md")


@api.route("/contest/<contest_id>/problem/hints/<problem_id>")
@api_login_required
def contest_problem_hint(contest_id, problem_id):
    from application import db
    if len(db.execute(("SELECT * FROM contest_problems WHERE "
                       "contest_id=:cid AND problem_id=:pid"),
                      cid=contest_id, pid=problem_id)) == 0:
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
