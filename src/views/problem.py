from flask import (Blueprint, flash, redirect, render_template, request,
                   send_file, session)
import logging
import os
import shutil
import zipfile
from io import BytesIO


from helpers import *  # noqa
from db import db

api = Blueprint("problem", __name__)

logger = logging.getLogger("CTFOJ")


@api.route('<problem_id>', methods=["GET", "POST"])
@login_required
def problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) != 1 or (data[0]["draft"] == 1 and not check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])):
        return render_template("problem/problem_noexist.html"), 404

    data[0]["editorial"] = read_file(f"metadata/problems/{problem_id}/editorial.md")
    data[0]["solved"] = db.execute(("SELECT COUNT(*) AS cnt FROM problem_solved WHERE "
                                    "user_id=? AND problem_id=?"),
                                   session["user_id"], problem_id)[0]["cnt"] == 1
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
    db.execute(("INSERT INTO submissions (user_id, problem_id, correct, submitted) "
                "VALUES (?, ?, ?, ?)"), session["user_id"], problem_id, check, flag)

    if not check:
        flash('The flag you submitted was incorrect', 'danger')
        return render_template('problem/problem.html', data=data[0])

    # Add entry into problem solve table
    try:
        db.execute("INSERT INTO problem_solved(user_id, problem_id) VALUES(:uid, :pid)",
                   uid=session["user_id"], pid=problem_id)
        # Award points if not already solved
        db.execute(("UPDATE users SET total_points=total_points+:pv, "
                    "problems_solved=problems_solved+1 WHERE id=:uid"),
                   pv=data[0]["point_value"], uid=session["user_id"])
    except ValueError:
        pass  # Already solved

    data[0]["solved"] = True
    flash('Congratulations! You have solved this problem!', 'success')
    return render_template('problem/problem.html', data=data[0])


@api.route('<problem_id>/publish', methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def publish_problem(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) != 1:
        return render_template("problem/problem_noexist.html"), 404

    r = db.execute("UPDATE problems SET draft=0 WHERE id=? AND draft=1", problem_id)
    if r == 1:
        logger.info(f"User #{session['user_id']} ({session['username']}) published {problem_id}",  # noqa
                    extra={"section": "problem"})
    flash('Problem successfully published', 'success')
    return redirect("/problem/" + problem_id)


@api.route('<problem_id>/editorial')
@login_required
def problem_editorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

    if data[0]["draft"] == 1 and not check_perm(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"]):
        return render_template("problem/problem_noexist.html"), 404

    return render_template('problem/problemeditorial.html', data=data[0])


@api.route('<problem_id>/edit', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
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
    new_description = (request.form.get("description") or "").replace('\r', '')
    new_hint = (request.form.get("hints") or "")
    new_category = request.form.get("category")
    new_points = int(request.form.get("point_value"))
    new_flag = request.form.get("flag")
    new_flag_hint = (request.form.get("flag_hint") or "")
    new_instanced = bool(request.form.get("instanced"))

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
        new_flag_hint = data[0]["flag_hint"]

    db.execute(("UPDATE problems SET name=:name, category=:category, point_value=:pv, "
                "flag=:flag, flag_hint=:fhint, instanced=:inst WHERE id=:problem_id"),
               name=new_name, category=new_category, pv=new_points,
               problem_id=problem_id, flag=new_flag, fhint=new_flag_hint,
               inst=new_instanced)
    db.execute(
        ("UPDATE users SET total_points=total_points+:dpv WHERE id IN "
         "(SELECT user_id FROM problem_solved WHERE problem_id=:pid)"),
        dpv=new_points - data[0]["point_value"], pid=problem_id
    )

    # Check if file exists & upload if it does
    file = request.files["file"]
    if file.filename:
        filename = problem_id + ".zip"
        file.save("dl/" + filename)
        if f'[{filename}](/dl/{filename})' not in new_description:
            new_description += f'\n\n[{filename}](/dl/{filename})'

    write_file('metadata/problems/' + problem_id + '/description.md', new_description)
    write_file('metadata/problems/' + problem_id + '/hints.md', new_hint)

    logger.info((f"User #{session['user_id']} ({session['username']}) edited problem "
                 f"{problem_id}"), extra={"section": "problem"})
    flash('Problem successfully edited', 'success')
    return redirect("/problem/" + problem_id)


@api.route('<problem_id>/editeditorial', methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def problem_editeditorial(problem_id):
    data = db.execute("SELECT * FROM problems WHERE id=:problem_id",
                      problem_id=problem_id)

    # Ensure problem exists
    if len(data) == 0:
        return render_template("problem/problem_noexist.html"), 404

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


@api.route('<problem_id>/delete', methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def delete_problem(problem_id):
    db.execute("BEGIN")
    data = db.execute("SELECT * FROM problems WHERE id=?", problem_id)
    if len(data) == 0:
        db.execute("COMMIT")
        return render_template("problem/problem_noexist.html"), 404
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


@api.route('<problem_id>/download')
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
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
