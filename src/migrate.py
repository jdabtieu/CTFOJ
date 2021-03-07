import cs50
import shutil
import sys
import re

msg = """Before migrating, please confirm the following:
 - You are on v2.0.0, v2.1.0, or v2.2.0 (older version please update to one of these first, new version no migrate necessary)
 - You have shut down the app. (Maintenance mode does not count)
 - You have made a backup of the database
 - You have write permissions in the current directory
 - No other process is using the database
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Additionally, this backup may take anywhere from a few minutes to close to an hour to complete, depending on the number of submissions.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

shutil.copy2('database.db', 'database.db.bak')
db = cs50.SQL("sqlite:///database.db")

# Check flags here
contest_flags = db.execute("SELECT * FROM contest_problems")
problem_flags = db.execute("SELECT * FROM problems")
invalid_flag = False
for row in contest_flags:
    if not re.match(r'^[ -~]{0,1024}$', row['flag']):
        print(f'{row["contest_id"]}: {row["problem_id"]}: flag invalid.')
        invalid_flag = True

for row in problem_flags:
    if not re.match(r'^[ -~]{0,1024}$', row['flag']):
        print(f'{row["id"]}: flag invalid.')
        invalid_flag = True

if invalid_flag:
    print('Please fix invalid flags before running this script again.')
    sys.exit()


# Change score table to allow dynamic scoring
db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_min' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_max' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_users' integer NOT NULL DEFAULT(-1)")

# Change submissions tables to allow for storing submissions
db.execute("ALTER TABLE submissions ADD COLUMN 'submitted' text NOT NULL DEFAULT('')")

last_num = db.execute("SELECT sub_id FROM submissions ORDER BY sub_id DESC LIMIT 1")[0]["sub_id"]
for submission in db.execute("SELECT * FROM submissions"):
    # Would probably be faster with multithreading but cs50.SQL really hates multithreading
    print(f"Processing submission {submission['sub_id']} of {last_num}...")
    if submission["correct"]:
        if submission["contest_id"]:
            flag = db.execute("SELECT * FROM contest_problems WHERE problem_id=? AND contest_id=?",
                              submission["problem_id"], submission["contest_id"])[0]["flag"]
        else:
            flag = db.execute("SELECT * FROM problems WHERE id=?", submission["problem_id"])[0]["flag"]
        db.execute("UPDATE submissions SET submitted=? WHERE sub_id=?", flag, submission["sub_id"])

print('Migration completed.')
