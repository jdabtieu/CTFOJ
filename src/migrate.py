import cs50
import sys
import hashlib

msg = """
Before migrating, please confirm the following:
 - You are on v4.1.x (older version please update to one of these first, new version no migrate necessary)
 - You have write permissions in the current directory
 - The site is shut down. For this migration, maintenance mode is not enough. The site should be completely down.
 - You have made a full database backup. This is a significant migration that can result in unexpected errors.
 - All API keys will be invalidated. You should tell API users to regenerate API keys after the migration.
Please note that migration is a one-way operation. Once it is completed, you will not be able to revert to the previous version without a database backup.

Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

db.execute("BEGIN")

def sha256sum(string):
    return hashlib.sha256(string.encode("utf-8")).hexdigest()

# Run checks
nusers = db.execute("SELECT COUNT(*) AS cnt FROM users")[0]["cnt"]
ndiff_username = db.execute("SELECT COUNT(DISTINCT username) AS cnt FROM users")[0]["cnt"]
ndiff_email = db.execute("SELECT COUNT(DISTINCT email) AS cnt FROM users")[0]["cnt"]

if ndiff_username != nusers:
    print("Some users have duplicate usernames. Fix that, then re-run this script.")
    sys.exit(1)
if ndiff_email != nusers:
    print("Some users have duplicate emails. Fix that, then re-run this script.")
    sys.exit(1)

nproblems = db.execute("SELECT COUNT(*) AS cnt FROM problems")[0]["cnt"]
ndiff_pids = db.execute("SELECT COUNT(DISTINCT id) AS cnt FROM problems")[0]["cnt"]

if ndiff_pids != nproblems:
    print("Some problems have duplicate IDs. Fix that, then re-run this script.")
    sys.exit(1)

ncontests = db.execute("SELECT COUNT(*) AS cnt FROM contests")[0]["cnt"]
ndiff_cids = db.execute("SELECT COUNT(DISTINCT id) AS cnt FROM contests")[0]["cnt"]

if ndiff_cids != ncontests:
    print("Some contests have duplicate IDs. Fix that, then re-run this script.")
    sys.exit(1)

ncusers = db.execute("SELECT COUNT(*) AS cnt FROM contest_users")[0]["cnt"]
ndiff_cusers = db.execute("SELECT COUNT(*) AS cnt FROM (SELECT DISTINCT contest_id, user_id FROM contest_users)")[0]["cnt"]

if ndiff_cusers != ncusers:
    print("Some users show up multiple times in contest_users. Find duplicate "
          "[user_id, contest_id] pairs and remove the duplicates, then re-run this script.")
    sys.exit(1)

ncsolves = db.execute("SELECT COUNT(*) AS cnt FROM contest_solved")[0]["cnt"]
ndiff_csolves = db.execute("SELECT COUNT(*) AS cnt FROM (SELECT DISTINCT contest_id, user_id, problem_id FROM contest_solved)")[0]["cnt"]

if ndiff_cusers != ncusers:
    bad_users = db.execute(("SELECT user_id, problem_id contest_id, cnt FROM ("
                                "SELECT user_id, problem_id, contest_id, COUNT(*) AS cnt FROM contest_solved GROUP BY user_id, problem_id, contest_id) "
                            "WHERE cnt > 1"))
    for user in bad_users:
        db.execute("DELETE FROM contest_solved WHERE user_id=? AND problem_id=? AND contest_id=?", user["user_id"], user["problem_id"], user["contest_id"])
        db.execute("INSERT INTO contest_solved (user_id, problem_id, contest_id) VALUES(?, ?, ?)", user["user_id"], user["problem_id"], user["contest_id"])

ncprobs = db.execute("SELECT COUNT(*) AS cnt FROM contest_problems")[0]["cnt"]
ndiff_cprobs = db.execute("SELECT COUNT(*) AS cnt FROM (SELECT DISTINCT contest_id, problem_id FROM contest_problems)")[0]["cnt"]

if ndiff_cprobs != ncprobs:
    print("Some contest(s) have multiple problems with the same IDs. Find duplicate "
          "[user_id, contest_id] pairs and remove the duplicates, then re-run this script.")

npsolves = db.execute("SELECT COUNT(*) AS cnt FROM problem_solved")[0]["cnt"]
ndiff_psolves = db.execute("SELECT COUNT(*) AS cnt FROM (SELECT DISTINCT user_id, problem_id FROM problem_solved)")[0]["cnt"]

if ndiff_psolves != npsolves:
    bad_users = db.execute(("SELECT user_id, problem_id, cnt FROM ("
                                "SELECT user_id, problem_id, COUNT(*) AS cnt FROM problem_solved GROUP BY user_id, problem_id) "
                            "WHERE cnt > 1"))
    for user in bad_users:
        db.execute("DELETE FROM problem_solved WHERE user_id=? AND problem_id=?", user["user_id"], user["problem_id"])
        db.execute("INSERT INTO problem_solved (user_id, problem_id) VALUES(?, ?)", user["user_id"], user["problem_id"])

# Rebuild database except for announcements
db.execute(
    ("CREATE TABLE 'users_tmp' ("
     "    'id' integer PRIMARY KEY NOT NULL,"
     "    'username' varchar(20) NOT NULL UNIQUE,"
     "    'password' varchar(64) NOT NULL,"
     "    'email' varchar(128) UNIQUE,"
     "    'join_date' datetime NOT NULL DEFAULT(0),"
     "    'banned' boolean NOT NULL DEFAULT(0),"
     "    'verified' boolean NOT NULL DEFAULT(0),"
     "    'twofa' boolean NOT NULL DEFAULT(0),"
     "    'api' varchar(256) UNIQUE,"
     "    'total_points' integer NOT NULL DEFAULT(0),"
     "    'contests_completed' integer NOT NULL DEFAULT(0),"
     "    'problems_solved' integer NOT NULL DEFAULT(0));"))
# api key deliberately not copied - invalidated
db.execute(("INSERT INTO users_tmp (id, username, password, email, join_date, banned, verified, twofa, total_points, contests_completed, problems_solved) "
            "SELECT                 id, username, password, email, join_date, banned, verified, twofa, total_points, contests_completed, problems_solved "
            "FROM users"))
db.execute("DROP TABLE users")
db.execute("ALTER TABLE users_tmp RENAME to users")

db.execute(
    ("CREATE TABLE 'user_perms_tmp' ("
     "    'user_id' integer NOT NULL,"
     "    'perm_id' integer NOT NULL,"
     "    UNIQUE(perm_id, user_id) ON CONFLICT IGNORE);"))
db.execute(("INSERT INTO user_perms_tmp (user_id, perm_id) "
            "SELECT                      user_id, perm_id "
            "FROM user_perms"))
db.execute("DROP TABLE user_perms")
db.execute("ALTER TABLE user_perms_tmp RENAME to user_perms")

db.execute(
    ("CREATE TABLE 'submissions_tmp' ("
     "    'id' integer PRIMARY KEY NOT NULL,"
     "    'date' datetime NOT NULL DEFAULT(datetime('now')),"
     "    'user_id' integer NOT NULL,"
     "    'problem_id' varchar(32) NOT NULL,"
     "    'contest_id' varchar(32),"
     "    'correct' boolean NOT NULL,"
     "    'submitted' text NOT NULL DEFAULT(''));"))
db.execute(("INSERT INTO submissions_tmp (id, date, user_id, problem_id, contest_id, correct, submitted) "
            "SELECT                       sub_id, date, user_id, problem_id, contest_id, correct, submitted "
            "FROM submissions"))
db.execute("DROP TABLE submissions")
db.execute("ALTER TABLE submissions_tmp RENAME to submissions")

db.execute(
    ("CREATE TABLE 'problems_tmp' ("
     "    'id' varchar(64) NOT NULL UNIQUE,"
     "    'name' varchar(256) NOT NULL,"
     "    'point_value' integer NOT NULL DEFAULT(0),"
     "    'category' varchar(64),"
     "    'flag' varchar(256) NOT NULL,"
     "    'draft' boolean NOT NULL DEFAULT(0),"
     "    'flag_hint' varchar(256) NOT NULL DEFAULT(''),"
     "    'instanced' boolean NOT NULL DEFAULT(0));"))
db.execute(("INSERT INTO problems_tmp (id, name, point_value, category, flag, draft, flag_hint, instanced) "
            "SELECT                    id, name, point_value, category, flag, draft, flag_hint, instanced "
            "FROM problems"))
db.execute("DROP TABLE problems")
db.execute("ALTER TABLE problems_tmp RENAME to problems")

db.execute(
    ("CREATE TABLE 'problem_solved_tmp' ("
     "    'user_id' integer NOT NULL,"
     "    'problem_id' varchar(64) NOT NULL,"
     "    UNIQUE(problem_id, user_id) ON CONFLICT ABORT);"))
db.execute(("INSERT INTO problem_solved_tmp (user_id, problem_id) "
            "SELECT                          user_id, problem_id "
            "FROM problem_solved"))
db.execute("DROP TABLE problem_solved")
db.execute("ALTER TABLE problem_solved_tmp RENAME to problem_solved")

db.execute(
    ("CREATE TABLE 'contests_tmp' ("
     "    'id' varchar(32) NOT NULL UNIQUE,"
     "    'name' varchar(256) NOT NULL,"
     "    'start' datetime NOT NULL,"
     "    'end' datetime NOT NULL,"
     "    'scoreboard_visible' boolean NOT NULL DEFAULT(1),"
     "    'scoreboard_key' varchar(36));"))
db.execute(("INSERT INTO contests_tmp (id, name, start, end, scoreboard_visible, scoreboard_key) "
            "SELECT                    id, name, start, end, scoreboard_visible, scoreboard_key "
            "FROM contests"))
db.execute("DROP TABLE contests")
db.execute("ALTER TABLE contests_tmp RENAME to contests")

db.execute(
    ("CREATE TABLE 'contest_users_tmp' ("
     "    'contest_id' varchar(32) NOT NULL,"
     "    'user_id' integer NOT NULL,"
     "    'points' integer NOT NULL DEFAULT (0),"
     "    'lastAC' datetime,"
     "    'hidden' integer NOT NULL DEFAULT(0),"
     "    UNIQUE(contest_id, user_id) ON CONFLICT ABORT);"))
db.execute(("INSERT INTO contest_users_tmp (contest_id, user_id, points, lastAC, hidden) "
            "SELECT                         contest_id, user_id, points, lastAC, hidden "
            "FROM contest_users"))
db.execute("DROP TABLE contest_users")
db.execute("ALTER TABLE contest_users_tmp RENAME to contest_users")

db.execute(
    ("CREATE TABLE 'contest_solved_tmp' ("
     "    'contest_id' varchar(32) NOT NULL,"
     "    'user_id' integer NOT NULL,"
     "    'problem_id' varchar(64) NOT NULL,"
     "    UNIQUE(contest_id, user_id, problem_id) ON CONFLICT ABORT);"))
db.execute(("INSERT INTO contest_solved_tmp (contest_id, user_id, problem_id) "
            "SELECT                          contest_id, user_id, problem_id "
            "FROM contest_solved"))
db.execute("DROP TABLE contest_solved")
db.execute("ALTER TABLE contest_solved_tmp RENAME to contest_solved")

db.execute(
    ("CREATE TABLE 'contest_problems_tmp' ("
     "    'contest_id' varchar(32) NOT NULL,"
     "    'problem_id' varchar(64) NOT NULL,"
     "    'name' varchar(256) NOT NULL,"
     "    'point_value' integer NOT NULL DEFAULT(0),"
     "    'category' varchar(64),"
     "    'flag' varchar(256) NOT NULL,"
     "    'draft' boolean NOT NULL DEFAULT(0),"
     "    'score_min' integer NOT NULL DEFAULT(0),"
     "    'score_max' integer NOT NULL DEFAULT(0),"
     "    'score_users' integer NOT NULL DEFAULT(-1),"
     "    'flag_hint' varchar(256) NOT NULL DEFAULT(''),"
     "    'instanced' boolean NOT NULL DEFAULT(0),"
     "    UNIQUE(contest_id, problem_id) ON CONFLICT ABORT);"))
db.execute(("INSERT INTO contest_problems_tmp (contest_id, problem_id, name, point_value, category, flag, draft, score_min, score_max, score_users, flag_hint, instanced) "
            "SELECT                            contest_id, problem_id, name, point_value, category, flag, draft, score_min, score_max, score_users, flag_hint, instanced "
            "FROM contest_problems"))
db.execute("DROP TABLE contest_problems")
db.execute("ALTER TABLE contest_problems_tmp RENAME to contest_problems")

db.execute("COMMIT")

print('Migration completed.')
