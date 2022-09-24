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

db = cs50.SQL("sqlite:///database.db")

db.execute('ALTER TABLE contest_problems ADD COLUMN "flag_hint" varchar(256) NOT NULL DEFAULT("")')

print('Migration completed.')
