import cs50
import sys

msg = """
Before migrating, please confirm the following:
 - You are on v4.0.x (older version please update to one of these first, new version no migrate necessary)
 - You have write permissions in the current directory
Please note that migration is a one-way operation. Once it is completed, you will not be able to revert to the previous version without a database backup.

Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

db.execute("BEGIN")

# Create new columns
db.execute("ALTER TABLE problems ADD COLUMN 'flag_hint' varchar(256) NOT NULL DEFAULT('')")
db.execute("ALTER TABLE problems ADD COLUMN 'instanced' boolean NOT NULL DEFAULT(0)")
db.execute("ALTER TABLE contest_problems ADD COLUMN 'instanced' boolean NOT NULL DEFAULT(0)")

db.execute("COMMIT")

print('Migration completed.')
