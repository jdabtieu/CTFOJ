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
