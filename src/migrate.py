import cs50
import sys

msg = """Before migrating, please confirm the following:
 - You are on v3.1.0 (older version please update to one of these first, new version no migrate necessary)
 - You have made a backup of the database
 - You have write permissions in the current directory
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

msg = """
You should back up all your data (dl, logs, metadata, database.db, settings.py) and then completely demolish the
CTFOJ directory. Then, completely reinstall CTFOJ, allow it to create the default files/db, and then
once that is completed, replace the autogenerated files with yours. Then, come back to this script."""

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

db.execute("ALTER TABLE users ADD COLUMN 'total_points' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE users ADD COLUMN 'contests_completed' integer NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE users ADD COLUMN 'problems_solved' integer NOT NULL DEFAULT(0)")

# TODO: Populate total_points
# TODO: Populate contests_completed
# TODO: Populate problems_solved

print('Migration completed.')
