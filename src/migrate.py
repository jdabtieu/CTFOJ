import cs50
import shutil
import sys
import re

msg = """Before migrating, please confirm the following:
 - You are on v2.3.0 or v2.3.1 (older version please update to one of these first, new version no migrate necessary)
 - You have made a backup of the database
 - You have write permissions in the current directory
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

db.execute("DELETE FROM problem_solved WHERE rowid NOT IN (SELECT min(rowid) FROM problem_solved GROUP BY user_id, problem_id)")

print('Migration completed.')
