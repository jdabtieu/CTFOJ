import cs50
import shutil
import sys

msg = """Before migrating, please confirm the following:
 - You are on v2.0.0, v2.1.0, or v2.2.0 (older version please update to one of these first, new version no migrate necessary)
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

db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_min' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_max' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE contest_problems ADD COLUMN 'score_users' integer NOT NULL DEFAULT(-1)")

# Migrate flags here
# bool(re.match(r'^[ -~]{0, 1024}$', text))

print('Migration completed.')
