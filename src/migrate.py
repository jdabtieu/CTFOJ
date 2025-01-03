import cs50
import sys

msg = """
Before migrating, please confirm the following:
 - You are on v4.2.x (older version please update to one of these first, new version no migrate necessary)
 - You have write permissions in the current directory
Please note that migration is a one-way operation. Once it is completed, you will not be able to revert to the previous version without a database backup.

Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")
db.execute("BEGIN")

db.execute("""CREATE TABLE 'problems_migration' (
    'id' varchar(64) NOT NULL UNIQUE,
    'name' varchar(256) NOT NULL,
    'point_value' integer NOT NULL DEFAULT(0),
    'category' varchar(64),
    'flag' varchar(256) NOT NULL,
    'status' integer NOT NULL DEFAULT(0),
    'flag_hint' varchar(256) NOT NULL DEFAULT(''),
    'instanced' boolean NOT NULL DEFAULT(0)
)""")
db.execute("INSERT INTO problems_migration SELECT id, name, point_value, category, flag, draft, flag_hint, instanced FROM problems")
db.execute("DROP TABLE problems")
db.execute("ALTER TABLE problems_migration RENAME TO problems")

db.execute("""CREATE TABLE 'contest_problems_migration' (
    'contest_id' varchar(32) NOT NULL,
    'problem_id' varchar(64) NOT NULL,
    'name' varchar(256) NOT NULL,
    'point_value' integer NOT NULL DEFAULT(0),
    'category' varchar(64),
    'flag' varchar(256) NOT NULL,
    'publish_timestamp' datetime DEFAULT(datetime('now')),
    'score_min' integer NOT NULL DEFAULT(0),
    'score_max' integer NOT NULL DEFAULT(0),
    'score_users' integer NOT NULL DEFAULT(-1),
    'flag_hint' varchar(256) NOT NULL DEFAULT(''),
    'instanced' boolean NOT NULL DEFAULT(0),
    UNIQUE(contest_id, problem_id) ON CONFLICT ABORT
);
""")
db.execute("INSERT INTO contest_problems_migration SELECT contest_id, problem_id, name, point_value, category, flag, draft, score_min, score_max, score_users, flag_hint, instanced FROM contest_problems")
db.execute("UPDATE contest_problems_migration SET publish_timestamp = datetime('now') WHERE publish_timestamp = 0")
db.execute("UPDATE contest_problems_migration SET publish_timestamp = NULL WHERE publish_timestamp = 1")
db.execute("DROP TABLE contest_problems")
db.execute("ALTER TABLE contest_problems_migration RENAME TO contest_problems")

db.execute("ALTER TABLE users ADD COLUMN 'registration_resend_attempts' integer NOT NULL DEFAULT(0)")

db.execute("COMMIT")

with open('settings.py', 'a') as f:
    f.write('''

"""
Limit the number of submissions that can be made per contest problem per user per minute.
This is used to prevent brute force attacks. Set to 0 to disable.
"""
SUBMIT_RATE_LIMIT_MIN = 45
SUBMIT_RATE_LIMIT_HOUR = 700
''')

print('Migration completed.')
