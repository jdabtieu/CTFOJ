import cs50
import shutil
import sys

msg = """Before migrating, please confirm the following:
 - You have shut down the app. (Maintenance mode does not count)
 - You have made a backup of the database
 - You have write permissions in the current directory
 - No other process is using the database
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

shutil.copy2('database.db', 'database.db.bak')
db = cs50.SQL("sqlite:///database.db")

db.execute("BEGIN")

# Copy problems_master to problems_solved
problems_master = db.execute("SELECT * FROM problems_master")
problems_list = db.execute("SELECT id FROM problems")

db.execute("CREATE TABLE 'problem_solved' ('user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL)")
for user in problems_master:
    for problem in problems_list:
        if user[problem["id"]]:
            db.execute("INSERT INTO problem_solved VALUES(:uid, :pid)", uid=user["user_id"], pid=problem["id"])

db.execute("DROP TABLE problems_master")


# Copy [contest_id]info to contest_problems
contests = db.execute("SELECT * FROM contests")

db.execute("CREATE TABLE 'contest_problems' ('contest_id' varchar(32) NOT NULL, 'problem_id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0))")

for contest in contests:
    cid = contest["id"]
    cidinfo = db.execute("SELECT * FROM :cidinfo", cidinfo=cid + "info")

    for problem in cidinfo:
        db.execute("INSERT INTO 'contest_problems' VALUES(:cid, :pid, :name, :pv, :category, :flag, :draft)", cid=cid, pid=problem["id"], name=problem["name"], pv=problem["point_value"], category=problem["category"], flag=problem["flag"], draft=problem["draft"])


# Copy contest users to contest_users
db.execute("CREATE TABLE 'contest_users' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'points' integer NOT NULL DEFAULT (0) , 'lastAC' datetime)")

for contest in contests:
    cid = contest["id"]
    users = db.execute("SELECT user_id, points, lastAC FROM :cid", cid=cid)

    for user in users:
        db.execute("INSERT INTO contest_users VALUES(:cid, :uid, :points, :lastAC)", cid=cid, uid=user["user_id"], points=user["points"], lastAC=user["lastAC"])


# Copy contest solved problem to contest_solved
db.execute("CREATE TABLE 'contest_solved' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL)")

for contest in contests:
    cid=contest["id"]
    users = db.execute("SELECT * FROM :cid", cid=cid)
    cidinfo = db.execute("SELECT * FROM :cidinfo", cidinfo=cid + "info")
    for user in users:
        for problem in cidinfo:
            if user[problem["id"]]:
                db.execute("INSERT INTO contest_solved VALUES(:cid, :uid, :pid)", cid=cid, uid=user["user_id"], pid=problem["id"])

    db.execute("DROP TABLE :cid", cid=cid)
    db.execute("DROP TABLE :cidinfo", cidinfo=cid + "info")

db.execute("COMMIT")

print('Migration completed.')
