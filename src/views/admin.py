from flask import (Blueprint, flash, redirect, render_template, request, session,
                   current_app as app)
import logging
import os
from werkzeug.security import generate_password_hash

from helpers import *  # noqa
from db import db

api = Blueprint("admin", __name__)

logger = logging.getLogger("CTFOJ")


@api.route("/console")
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def admin_console():
    maintenance_mode = os.path.exists('maintenance_mode')
    if maintenance_mode:
        msg = read_file('maintenance_mode')
    else:
        msg = ""
    return render_template("admin/console.html", ver="v4.2.3",
                           maintenance_mode=maintenance_mode, maintenance_msg=msg)


@api.route("/submissions")
@perm_required(["ADMIN", "SUPERADMIN", "PROBLEM_MANAGER", "CONTENT_MANAGER"])
def admin_submissions():
    submissions = None

    query = request.args
    modifier = " WHERE"
    args = []

    # Construct query
    if query.get("username"):
        modifier += " username=? AND"
        args.append(query.get("username"))

    if query.get("problem_id"):
        modifier += " problem_id=? AND"
        args.append(query.get("problem_id"))

    if query.get("contest_id"):
        if (query.get("contest_id") == "None" or
                not check_perm(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])):
            modifier += " contest_id IS NULL AND"
        else:
            modifier += " contest_id=? AND"
            args.append(query.get("contest_id"))

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

    return render_template("admin/submissions.html",
                           data=submissions, length=-(-length // 50))


@api.route("/users")
@admin_required
def admin_users():
    query = request.args.get("q")
    modifier = ""
    args = []
    if query:
        modifier = "WHERE username LIKE ? OR email LIKE ?"
        query = '%' + query + '%'
        args = [query, query]

    page = request.args.get("page")
    if not page:
        page = "1"
    page = (int(page) - 1) * 50

    data = db.execute((f"SELECT * FROM users {modifier} ORDER BY id ASC "
                       "LIMIT 50 OFFSET ?"), *args, page)
    length = db.execute(f"SELECT COUNT(*) AS cnt FROM users {modifier}", *args)[0]["cnt"]

    perms = db.execute("SELECT * FROM user_perms WHERE user_id IN (?)",
                       [u["id"] for u in data])
    disp_perms = {}
    for perm in perms:
        if perm["user_id"] not in disp_perms:
            disp_perms[perm["user_id"]] = {}
        disp_perms[perm["user_id"]][perm["perm_id"]] = True

    return render_template("admin/users.html", data=data, length=-(-length // 50),
                           perm_list=USER_PERM, disp_perms=disp_perms)


@api.route("/ban", methods=["POST"])
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

    ban_perm = db.execute("SELECT * FROM user_perms WHERE user_id=?", user_id)
    ban_perm = set([x["perm_id"] for x in ban_perm])
    if check_perm(["ADMIN", "SUPERADMIN"], ban_perm) and not check_perm(["SUPERADMIN"]):
        flash("Only super-admins can ban admins", "danger")
        return redirect("/admin/users")

    db.execute("UPDATE users SET banned=:status WHERE id=:id",
               status=not user["banned"], id=user_id)

    msg = "unbanned" if user["banned"] else "banned"
    flash(f"Successfully {msg} {user['username']}", "success")
    logger.info((f"User #{user_id} ({user['username']}) {msg} by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "auth"})
    return redirect("/admin/users")


@api.route("/resetpass", methods=["POST"])
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

    perm = db.execute("SELECT * FROM user_perms WHERE user_id=?", user[0]["id"])
    perm = set([x["perm_id"] for x in perm])
    if check_perm(["SUPERADMIN"], perm):
        flash(("Cannot reset super-admin passwords. Super-admins must "
               "use the forgot password page instead."), "danger")
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


@api.route("/updateperms", methods=["POST"])
@admin_required
def update_perms():
    user_id = request.args.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    db.execute("BEGIN")
    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)
    if len(user) == 0:
        db.execute("COMMIT")
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")
    user_id = int(user_id)

    cur_perms = db.execute("SELECT * FROM user_perms WHERE user_id=?", user_id)
    cur_perms = set([x["perm_id"] for x in cur_perms])
    new_perms = set([int(x) for x in request.form.getlist("perms")])

    # Calculate old/new perms
    perms_add = new_perms - cur_perms
    perms_remove = cur_perms - new_perms
    if not perms_add and not perms_remove:
        db.execute("COMMIT")
        flash("No perms were updated", "warning")
        return redirect("/admin/users")

    # Get friendly names
    inv_perms = {v: k for k, v in USER_PERM.items()}
    friendly_perms_add = [inv_perms[x] for x in perms_add]
    friendly_perms_remove = [inv_perms[x] for x in perms_remove]

    # Permission checks for sensitive permissions
    if check_perm(["ADMIN", "SUPERADMIN"], perms_remove) and not check_perm(["SUPERADMIN"]):
        db.execute("COMMIT")
        flash("Only the super-admin can revoke admin status", "danger")
        return redirect("/admin/users")

    if check_perm(["SUPERADMIN"], perms_add) and not check_perm(["SUPERADMIN"]):
        db.execute("COMMIT")
        flash("Only the super-admin can create super-admins", "danger")
        return redirect("/admin/users")

    # Update permissions
    for perm in perms_add:
        db.execute("INSERT INTO user_perms(user_id, perm_id) VALUES(?, ?)", user_id, perm)
    db.execute("DELETE FROM user_perms WHERE user_id=? AND perm_id IN (?)",
               user_id, list(perms_remove))
    db.execute("COMMIT")

    # Flash and log message
    msg = f"Permissions changed for user #{user_id} ({user[0]['username']}). "
    if friendly_perms_add:
        msg += f"Granted {friendly_perms_add}. "
    if friendly_perms_remove:
        msg += f"Revoked {friendly_perms_remove}. "
    flash(msg, "success")
    logger.info(msg + f" Performed by user #{session['user_id']} ({session['username']})",
                extra={"section": "auth"})
    return redirect("/admin/users")


@api.route("/verify", methods=["POST"])
@admin_required
def verify_user():
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Must provide user ID", "danger")
        return redirect("/admin/users")

    user = db.execute("SELECT * FROM users WHERE id=:id", id=user_id)

    if len(user) == 0:
        flash("That user doesn't exist", "danger")
        return redirect("/admin/users")

    if user[0]["verified"]:
        flash("That user is already verified", "warning")
        return redirect("/admin/users")

    db.execute("UPDATE users SET verified=1 WHERE id=:id", id=user_id)

    flash(f"{user[0]['username']} is now verified.", "success")
    logger.info((f"User #{user_id} ({user[0]['username']}) manually verified by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "auth"})
    return redirect("/admin/users")


@api.route("/createannouncement", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
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


@api.route("/deleteannouncement", methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def delete_announcement():
    aid = request.form.get("aid")
    if not aid:
        return "Must provide announcement ID", 400

    r = db.execute("DELETE FROM announcements WHERE id=?", aid)
    if r == 0:
        flash("That announcement doesn't exist", "warning")
        return redirect("/")
    os.remove('metadata/announcements/' + aid + '.md')

    logger.info((f"User #{session['user_id']} ({session['username']}) deleted "
                 f"announcement {aid}"), extra={"section": "announcement"})
    flash('Announcement successfully deleted', 'success')
    return redirect("/")


@api.route("/editannouncement/<aid>", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
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


@api.route("/maintenance/enable", methods=["POST"])
@admin_required
def enable_maintenance():
    msg = request.form.get("message") or ""
    write_file('maintenance_mode', msg)
    flash("Enabled maintenance mode", "success")

    logger.info(("Enabled maintenance mode by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "misc"})
    return redirect('/admin/console')


@api.route("/maintenance/disable", methods=["POST"])
@admin_required
def disable_maintenance():
    os.remove('maintenance_mode')
    flash("Disabled maintenance mode", "success")

    logger.info(("Disabled maintenance mode by "
                 f"user #{session['user_id']} ({session['username']})"),
                extra={"section": "misc"})
    return redirect('/admin/console')


@api.route("/edithomepage", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def edit_homepage():
    data = read_file(app.config['HOMEPAGE_FILE'])[2:]
    if request.method == "GET":
        return render_template("admin/edithomepage.html", data=data)

    # Reached via POST

    layout_method = request.form.get("method")
    content = request.form.get("content")

    if not content:
        flash('To disable the homepage, edit settings.py instead', 'danger')
        return render_template("admin/edithomepage.html", data=data), 400
    if not layout_method or layout_method not in ["1", "2"]:
        layout_method = "1"

    content = layout_method + "\n" + content.replace('\r', '')

    write_file(app.config['HOMEPAGE_FILE'], content)

    logger.info(f"User #{session['user_id']} ({session['username']}) updated the homepage ",  # noqa
                extra={"section": "announcement"})
    flash("You have successfully edited the homepage!", "success")
    return redirect("/admin/previewhomepage")


@api.route("/previewhomepage")
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def preview_homepage():
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


@api.route("/staticpages")
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def list_static_pages():
    data = db.execute("SELECT * FROM static_pages")
    return render_template("admin/staticpages.html", data=data)

@api.route("/staticpages/create", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def create_static_page():
    if request.method == "GET":
        return render_template("admin/createstaticpage.html")
    
    # Reached via POST
    title = request.form.get("title")
    path = request.form.get("path")
    content = request.form.get("content")

    if not title or not path or not content:
        flash('You have not entered all required fields', 'danger')
        return render_template("admin/createstaticpage.html"), 400
    path = path.strip().strip('/').lower()

    db.execute("INSERT INTO static_pages (title, path, content) VALUES (?, ?, ?)",
               title, path, content)
    return redirect("/admin/staticpages")

@api.route("/staticpages/delete", methods=["POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def delete_static_page():
    page_id = request.form.get("page_id")
    if not page_id:
        return "Must provide page ID", 400

    r = db.execute("DELETE FROM static_pages WHERE id=?", page_id)
    if r == 0:
        flash("That page doesn't exist", "warning")
        return redirect("/admin/staticpages")

    return redirect("/admin/staticpages")

@api.route("/staticpages/edit/<pid>", methods=["GET", "POST"])
@perm_required(["ADMIN", "SUPERADMIN", "CONTENT_MANAGER"])
def edit_static_page(pid):
    data = db.execute("SELECT * FROM static_pages WHERE id=?", pid)
    if len(data) == 0:
        flash('That page does not exist', 'danger')
        return redirect("/admin/staticpages")

    data = data[0]
    if request.method == "GET":
        return render_template("admin/editstaticpage.html", data=data)
    
    # Reached via POST
    title = request.form.get("title")
    path = request.form.get("path")
    content = request.form.get("content")

    if not title or not path or not content:
        flash('You have not entered all required fields', 'danger')
        return render_template("admin/editstaticpage.html"), 400
    path = path.strip().strip('/').lower()

    db.execute("UPDATE static_pages SET title=?, path=?, content=? WHERE id=?",
               title, path, content, pid)
    flash("Page successfully updated", "success")
    return redirect("/admin/staticpages")