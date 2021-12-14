import cs50
import shutil
import sys

msg = """Before migrating, please confirm the following:
 - You are on v2.4.0 to v2.4.3 (older version please update to one of these first, new version no migrate necessary)
 - You have made a backup of the database
 - You have write permissions in the current directory
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

## TODO: add missing submissions from contest problem exports
db.execute("ALTER TABLE contest_users ADD COLUMN 'hidden' integer NOT NULL DEFAULT(0)")

print('Migration completed.')
