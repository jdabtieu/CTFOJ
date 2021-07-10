from flask import (Blueprint, make_response, send_from_directory, session)

from helpers import *  # noqa

api = Blueprint("api", __name__)


@api.route("/problem/description/<problem_id>")
def problem_description(problem_id):
    from application import db
    if not session or "user_id" not in session:
        return make_response(("Unauthorized", 401))
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "description.md")


@api.route("/problem/hints/<problem_id>")
def problem_hint(problem_id):
    from application import db
    if not session or "user_id" not in session:
        return make_response(("Unauthorized", 401))
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "hints.md")


@api.route("/problem/editorial/<problem_id>")
def problem_editorial(problem_id):
    from application import db
    if not session or "user_id" not in session:
        return make_response(("Unauthorized", 401))
    if len(db.execute("SELECT * FROM problems WHERE id=:pid", pid=problem_id)) == 0:
        return make_response(("Problem not found", 404))
    return send_from_directory(f"metadata/problems/{problem_id}", "editorial.md")
