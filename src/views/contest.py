from enum import Enum
from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session, current_app as app)
import logging
import os
import shutil
import zipfile
from datetime import datetime
from io import BytesIO


from helpers import *  # noqa
from db import db

api = Blueprint("contest", __name__)

logger = logging.getLogger("CTFOJ")


class CUser(Enum):
    NORMAL = 0
    HIDDEN = 1
    BANNED = 2


def _insert_user_into_contest(user_id, contest_row):
    """
    Inserts a user into a contest if they are not already in it and the contest is not over.
    """
    if datetime.utcnow() >= parse_datetime(contest_row["end"]):
        return
    db.execute("INSERT INTO contest_users (contest_id, user_id) VALUES(:cid, :uid)",
                cid=contest_row["id"], uid=user_id)
    db.execute("UPDATE users SET contests_completed=contests_completed+1 WHERE id=?",
                user_id)


@api.route("/<contest_id>")
@login_required
def contest(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest started or user is admin
    start = parse_datetime(contest_info[0]["start"])
    if datetime.utcnow() < start and not check_perm(["ADMIN", "SUPERADMIN"]):
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    title = contest_info[0]["name"]
    scoreboard_key = contest_info[0]["scoreboard_key"]

    db.execute("BEGIN")
    user_info = db.execute(
        "SELECT * FROM contest_users WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])

    if len(user_info) == 0:
        _insert_user_into_contest(session["user_id"], contest_info[0])

    solved_info = db.execute(
        "SELECT problem_id FROM contest_solved WHERE contest_id=:cid AND user_id=:uid",
        cid=contest_id, uid=session["user_id"])
    solved_data = set([x["problem_id"] for x in solved_info])

    data = []
    info = db.execute(
        ("SELECT * FROM contest_problems WHERE contest_id=:cid AND status=0 "
         "GROUP BY problem_id ORDER BY problem_id ASC, category ASC;"),
        cid=contest_id)

    solves = db.execute(("SELECT problem_id, COUNT(user_id) AS solves FROM "
                         "contest_solved WHERE contest_id=:cid AND user_id NOT IN ("
                         "SELECT user_id FROM contest_users WHERE contest_id=:cid AND "
                         "hidden != 0) GROUP BY problem_id"), cid=contest_id)
    solve_count = {x["problem_id"]: x["solves"] for x in solves}
    db.execute("COMMIT")

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

    return render_template("contest/contest.html", title=title,
                           scoreboard_key=scoreboard_key, data=data)


@api.route('/<contest_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
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


@api.route("/<contest_id>/delete", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def delete_contest(contest_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html")

    if request.method == "GET":
        return render_template("contest/delete_confirm.html", data=contest_id)

    # Reached using POST

    db.execute("BEGIN")
    db.execute(("UPDATE users SET contests_completed=contests_completed-1 WHERE id IN "
                "(SELECT id FROM contest_users WHERE contest_id=?)"), contest_id)
    db.execute("DELETE FROM contests WHERE id=?", contest_id)
    db.execute("DELETE FROM contest_users WHERE contest_id=?", contest_id)
    db.execute("DELETE FROM contest_solved WHERE contest_id=?", contest_id)
    db.execute("DELETE FROM contest_problems WHERE contest_id=?", contest_id)
    db.execute("COMMIT")

    shutil.rmtree('metadata/contests/' + contest_id)

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"contest {contest_id}"), extra={"section": "contest"})
    flash('Contest successfully deleted', 'success')
    return redirect("/contests")


@api.route("/<contest_id>/notify", methods=['GET', 'POST'])
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


@api.route("/<contest_id>/drafts")
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def contest_drafts(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    data = db.execute("SELECT * FROM contest_problems WHERE contest_id=:cid AND status=1",
                      cid=contest_id)

    return render_template("contest/draft_problems.html",
                           title=contest_info[0]["name"], data=data)


@api.route("/<contest_id>/problem/<problem_id>", methods=["GET", "POST"])
@login_required
def contest_problem(contest_id, problem_id):
    # Ensure contest and problem exist
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest started or user is admin
    contest_info = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if (datetime.utcnow() < parse_datetime(contest_info[0]["start"])
            and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    check = db.execute(("SELECT * FROM contest_problems WHERE contest_id=:cid AND "
                        "problem_id=:pid"),
                       cid=contest_id, pid=problem_id)
    if len(check) != 1 or (check[0]["status"] == PROBLEM_STAT["DRAFT"]
            and not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
        return render_template("contest/contest_problem_noexist.html"), 404

    # Check if problem is solved
    check[0]["solved"] = db.execute(
        ("SELECT COUNT(*) AS cnt FROM contest_solved WHERE contest_id=? AND "
         "problem_id=? AND user_id=?"),
        contest_id, problem_id, session["user_id"])[0]["cnt"]

    if request.method == "GET":
        return render_template("contest/contest_problem.html", data=check[0])

    # Reached via POST

    # Ensure contest hasn't ended
    if contest_ended(db.execute("SELECT end FROM contests WHERE id=:id", id=contest_id)):
        flash('This contest has ended', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    # Check if user is banned from this contest
    user = db.execute("SELECT * FROM contest_users WHERE user_id=? AND contest_id=?",
                      session["user_id"], contest_id)
    if len(user) > 0 and user[0]["hidden"] == CUser.BANNED.value:
        flash('You are banned from this contest', 'danger')
        return render_template("contest/contest_problem.html", data=check[0])
    if len(user) == 0:
        _insert_user_into_contest(session["user_id"], contest_info[0])

    if not check[0]["solved"]:
        submit_rate_limited = check_submit_rate_limit(contest_id, problem_id)
        if submit_rate_limited:
            flash(submit_rate_limited, 'warning')
            return render_template("contest/contest_problem.html", data=check[0]), 400

    flag = request.form.get("flag")
    if not flag or not verify_flag(flag):
        flash('Invalid flag', 'danger')
        return render_template("contest/contest_problem.html", data=check[0]), 400

    flag_correct = flag == check[0]["flag"]
    db.execute(("INSERT INTO submissions(user_id, problem_id, contest_id, correct, "
                "submitted) VALUES(?, ?, ?, ?, ?)"),
               session["user_id"], problem_id, contest_id, flag_correct, flag)

    # Check if flag is correct
    if not flag_correct:
        flash('Your flag is incorrect', 'danger')
        return render_template("contest/contest_problem.html", data=check[0])

    # Check if user has already found this flag
    db.execute("BEGIN")
    check1 = db.execute(("SELECT * FROM contest_solved WHERE contest_id=:cid "
                         "AND user_id=:uid AND problem_id=:pid"),
                        cid=contest_id, uid=session["user_id"], pid=problem_id)
    if len(check1) == 0:
        if check[0]["score_users"] != -1 and user[0]["hidden"] == CUser.NORMAL.value:
            # Dynamic scoring
            update_dyn_score(contest_id, problem_id)
        else:  # Static scoring
            db.execute(("INSERT INTO contest_solved(contest_id, user_id, problem_id) "
                        "VALUES(:cid, :uid, :pid)"),
                       cid=contest_id, pid=problem_id, uid=session["user_id"])
            points = check[0]["point_value"]
            db.execute(("UPDATE contest_users SET lastAC=datetime('now'), "
                        "points=points+:points WHERE contest_id=:cid AND user_id=:uid"),
                       cid=contest_id, points=points, uid=session["user_id"])
    db.execute("COMMIT")

    flash('Congratulations! You have solved this problem!', 'success')
    return redirect(f"/contest/{contest_id}/problem/{problem_id}")


@api.route("/<contest_id>/problem/<problem_id>/publish", methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def publish_contest_problem(contest_id, problem_id):
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    r = db.execute(
        "UPDATE contest_problems SET status=0 WHERE problem_id=? AND contest_id=?",
        problem_id, contest_id)
    if r == 0:
        return render_template("contest/contest_problem_noexist.html"), 404

    logger.info((f"User #{session['user_id']} ({session['username']}) published "
                 f"{problem_id} from contest {contest_id}"), extra={"section": "contest"})
    flash('Problem successfully published', 'success')
    return redirect("/contest/" + contest_id + "/problem/" + problem_id)


@api.route('/<contest_id>/problem/<problem_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def edit_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    data = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(data) == 0:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        return render_template('contest/edit_problem.html', data=data[0])

    # Reached via POST

    new_name = request.form.get("name")
    new_description = (request.form.get("description") or "").replace('\r', '')
    new_hint = (request.form.get("hints") or "")
    new_category = request.form.get("category")
    new_points = request.form.get("point_value")
    new_flag = request.form.get("flag")
    new_flag_hint = (request.form.get("flag_hint") or "")
    new_instanced = bool(request.form.get("instanced"))

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

    # Only edit score for statically scored problems whose value has changed
    if data[0]["score_users"] == -1 and data[0]["point_value"] != new_points:
        point_change = int(new_points) - data[0]["point_value"]
        db.execute("BEGIN")
        db.execute(("UPDATE contest_users SET points=points+:point_change WHERE "
                    "contest_id=:cid AND user_id IN (SELECT user_id FROM contest_solved "
                    "WHERE contest_id=:cid AND problem_id=:pid)"),
                   point_change=point_change, cid=contest_id, pid=problem_id)
        db.execute(("UPDATE contest_problems SET point_value=:pv WHERE contest_id=:cid "
                    "AND problem_id=:pid"),
                   pv=int(new_points), cid=contest_id, pid=problem_id)
        db.execute("COMMIT")

    db.execute(("UPDATE contest_problems SET name=:name, category=:category, flag=:flag, "
                "flag_hint=:fhint, instanced=:inst WHERE contest_id=:cid AND problem_id=:pid"),
               name=new_name, category=new_category, flag=new_flag, cid=contest_id,
               pid=problem_id, fhint=new_flag_hint, inst=new_instanced)
    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        if not os.path.exists("dl/" + contest_id):
            os.makedirs("dl/" + contest_id)
        filename = problem_id + ".zip"
        filepath = "dl/" + contest_id + "/"
        file.save(filepath + filename)
        if f'[{filename}](/{filepath + filename})' not in new_description:
            new_description += f'\n\n[{filename}](/{filepath + filename})'
    write_file(
        f'metadata/contests/{contest_id}/{problem_id}/description.md', new_description)
    write_file(f'metadata/contests/{contest_id}/{problem_id}/hints.md', new_hint)

    logger.info((f"User #{session['user_id']} ({session['username']}) edited problem "
                 f"{problem_id} in contest {contest_id}"),
                extra={"section": "contest"})
    flash('Problem successfully edited', 'success')
    return redirect(f"/contest/{contest_id}/problem/{problem_id}")


@api.route("/<contest_id>/scoreboard")
@login_required
def contest_scoreboard(contest_id):
    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure proper permissions
    if not (contest_info[0]["scoreboard_visible"] or check_perm(["ADMIN", "SUPERADMIN"])):
        flash('You are not allowed to view the scoreboard!', 'danger')
        return redirect("/contest/" + contest_id)

    data = db.execute(
        ("SELECT user_id, points, lastAC, username FROM contest_users "
         "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
         "hidden=0 ORDER BY points DESC, lastAC ASC"),
        cid=contest_id)

    if check_perm(["ADMIN", "SUPERADMIN"]):
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username, hidden FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 ORDER BY points DESC, lastAC ASC"),
            cid=contest_id)
        hidden += db.execute(  # Put banned users at the bottom of the list
            ("SELECT user_id, points, lastAC, username, hidden FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=2 ORDER BY points DESC, lastAC ASC"),
            cid=contest_id)
    else:
        hidden = db.execute(
            ("SELECT user_id, points, lastAC, username, hidden FROM contest_users "
             "JOIN users on user_id=users.id WHERE contest_users.contest_id=:cid AND "
             "hidden=1 AND user_id=:uid ORDER BY points DESC, lastAC ASC"),
            cid=contest_id, uid=session["user_id"])

    return render_template("contest/scoreboard.html",
                           title=contest_info[0]["name"], data=data, hidden=hidden)


def _contest_hide(contest_id, hide_enum, hide_msg):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute("BEGIN")
    stat = db.execute("SELECT hidden FROM contest_users WHERE user_id=? AND contest_id=?",
                      user_id, contest_id)
    if len(stat) == 0:
        db.execute("ROLLBACK")
        flash("That user is not present in the contest", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute("UPDATE contest_users SET hidden=? WHERE user_id=? AND contest_id=?",
               hide_enum, user_id, contest_id)
    if stat[0]["hidden"] == 0:  # We need to update dynscore
        updatelist = db.execute(
            ("SELECT contest_solved.problem_id FROM contest_solved INNER JOIN "
             "contest_problems ON contest_solved.problem_id=contest_problems.problem_id "
             "WHERE user_id=? AND contest_solved.contest_id=? AND "
             "contest_problems.contest_id=? AND contest_problems.score_users != -1"),
            user_id, contest_id, contest_id)
        for problem in updatelist:
            update_dyn_score(contest_id, problem["problem_id"], False, -1)

    db.execute("COMMIT")
    flash(f"User successfully {hide_msg}!", "success")
    logger.info((f"User #{user_id} {hide_msg} from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


def _contest_unhide(contest_id, hide_msg):
    # Ensure contest exists
    if not contest_exists(contest_id):
        return render_template("contest/contest_noexist.html"), 404

    user_id = request.form.get("user_id")
    if not user_id:
        flash("No user ID specified, please try again", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute("BEGIN")
    stat = db.execute("SELECT hidden FROM contest_users WHERE user_id=? AND contest_id=?",
                      user_id, contest_id)
    if len(stat) == 0:
        db.execute("ROLLBACK")
        flash("That user is not present in the contest", "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")
    if stat[0]["hidden"] == 0:
        db.execute("ROLLBACK")
        flash("That user is not " + hide_msg, "danger")
        return redirect("/contest/" + contest_id + "/scoreboard")

    db.execute("UPDATE contest_users SET hidden=0 WHERE user_id=? AND contest_id=?",
               user_id, contest_id)
    # We need to update dynscore
    updatelist = db.execute(
        ("SELECT contest_solved.problem_id FROM contest_solved INNER JOIN "
            "contest_problems ON contest_solved.problem_id=contest_problems.problem_id "
            "WHERE user_id=? AND contest_solved.contest_id=? AND "
            "contest_problems.contest_id=? AND contest_problems.score_users != -1"),
        user_id, contest_id, contest_id)
    for problem in updatelist:
        update_dyn_score(contest_id, problem["problem_id"], False)

    db.execute("COMMIT")
    flash(f"User successfully un{hide_msg}!", "success")
    logger.info((f"User #{user_id} un{hide_msg} from contest {contest_id} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "contest"})
    return redirect("/contest/" + contest_id + "/scoreboard")


@api.route("/<contest_id>/scoreboard/ban", methods=["POST"])
@admin_required
def contest_dq(contest_id):
    return _contest_hide(contest_id, CUser.BANNED.value, "banned")


@api.route("/<contest_id>/scoreboard/hide", methods=["POST"])
@admin_required
def contest_hide(contest_id):
    return _contest_hide(contest_id, CUser.HIDDEN.value, "hidden")


@api.route("/<contest_id>/scoreboard/unban", methods=["POST"])
@admin_required
def contest_unban(contest_id):
    return _contest_unhide(contest_id, "banned")


@api.route("/<contest_id>/scoreboard/unhide", methods=["POST"])
@admin_required
def contest_unhide(contest_id):
    return _contest_unhide(contest_id, "hidden")


@api.route("/<contest_id>/addproblem", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
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
    description = (request.form.get("description") or '').replace('\r', '')
    hints = request.form.get("hints")
    category = request.form.get("category")
    flag = request.form.get("flag")
    draft = 1 if request.form.get("draft") else 0
    flag_hint = request.form.get("flag_hint")
    if not flag_hint:
        flag_hint = ""
    instanced = bool(request.form.get("instanced"))

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
        try:
            db.execute(("INSERT INTO contest_problems VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                       contest_id, problem_id, name, max_points, category, flag, draft,
                       min_points, max_points, users_decay, flag_hint, instanced)
        except ValueError:
            flash('A problem with this ID already exists', 'danger')
            return render_template("contest/create_problem.html"), 409
    else:  # assume static
        point_value = request.form.get("point_value")
        if not point_value:
            flash('You have not entered all required fields', 'danger')
            return render_template("contest/create_problem.html"), 400

        # Modify problems table
        try:
            db.execute(("INSERT INTO contest_problems(contest_id, problem_id, name, "
                        "point_value, category, flag, status, flag_hint, instanced) "
                        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)"),
                       contest_id, problem_id, name, point_value, category, flag, draft,
                       flag_hint, instanced)
        except ValueError:
            flash('A problem with this ID already exists', 'danger')
            return render_template("contest/create_problem.html"), 409

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


@api.route('/<contest_id>/problem/<problem_id>/export', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def export_contest_problem(contest_id, problem_id):
    # Ensure contest exists
    cdata = db.execute("SELECT * FROM contests WHERE id=:cid", cid=contest_id)
    if len(cdata) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure problem exists
    pdata = db.execute(
        "SELECT * FROM contest_problems WHERE contest_id=:cid AND problem_id=:pid",
        cid=contest_id, pid=problem_id)
    if len(pdata) != 1:
        return render_template("contest/contest_problem_noexist.html"), 404

    if request.method == "GET":
        if not contest_ended(cdata):
            flash("Are you sure? The contest hasn't ended yet", 'warning')
        return render_template('contest/export_problem.html', data=pdata[0])

    # Reached via POST

    new_id = contest_id + "-" + problem_id  # this should be safe already
    new_name = cdata[0]["name"] + " - " + pdata[0]["name"]
    new_points = request.form.get("point_value") or pdata[0]["point_value"]

    # Insert into problems databases
    try:
        db.execute(("INSERT INTO problems(id, name, point_value, category, flag, "
                    "flag_hint, instanced) VALUES(?, ?, ?, ?, ?, ?, ?)"),
                   new_id, new_name, new_points, pdata[0]["category"], pdata[0]["flag"],
                   pdata[0]["flag_hint"], pdata[0]["instanced"])
    except ValueError:
        flash(('This problem has already been exported, or a problem with '
               f'ID {new_id} already exists'), 'danger')
        return render_template('contest/export_problem.html', data=pdata[0])

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


@api.route('/<contest_id>/problem/<problem_id>/download')
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
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


@api.route("/<contest_id>/submissions")
@login_required
def contest_submissions(contest_id):
    if check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"]):
        return redirect("/admin/submissions?contest_id=" + contest_id)

    # Ensure contest exists
    contest_info = db.execute("SELECT * FROM contests WHERE id=?", contest_id)
    if len(contest_info) != 1:
        return render_template("contest/contest_noexist.html"), 404

    # Ensure contest started or user is admin
    start = parse_datetime(contest_info[0]["start"])
    if datetime.utcnow() < start:
        flash('The contest has not started yet!', 'danger')
        return redirect("/contests")

    submissions = None

    query = request.args
    modifier = " WHERE username=? AND contest_id=? AND"
    args = [session["username"], contest_id]

    # Construct query
    if query.get("problem_id"):
        modifier += " problem_id=? AND"
        args.append(query.get("problem_id"))

    if query.get("correct"):
        modifier += " correct=? AND"
        args.append(query.get("correct") == "AC")

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50
    modifier += " 1=1"

    length = db.execute(("SELECT COUNT(*) AS cnt FROM submissions LEFT JOIN users ON "
                         "user_id=users.id") + modifier, *args)[0]["cnt"]

    args.append(page)
    submissions = db.execute(("SELECT submissions.*, users.username FROM submissions "
                              f"LEFT JOIN users ON user_id=users.id {modifier}"
                              " LIMIT 50 OFFSET ?"), *args)

    return render_template("contest/submissions.html",
                           data=submissions, length=-(-length // 50))
