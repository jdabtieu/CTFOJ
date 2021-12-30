import cs50
import sys

msg = """Before migrating, please confirm the following:
 - You are on v3.0.0 to v3.0.1 (older version please update to one of these first, new version no migrate necessary)
 - You have made a backup of the database
 - You have write permissions in the current directory
Please note that migration is a one-way operation, and you will not be able to revert to the previous version without a backup.
Are you sure you wish to migrate? [y/n] """

confirm = input(msg)
if confirm != 'y':
    print('Aborting...')
    sys.exit()

db = cs50.SQL("sqlite:///database.db")

db.execute('ALTER TABLE contest_users ADD COLUMN "hidden" integer NOT NULL DEFAULT(0)')

exportable = db.execute('SELECT * FROM submissions WHERE contest_id IS NOT NULL')
problem_ids = set([e['id'] for e in db.execute('SELECT id FROM problems')])
i = 1
for sub in exportable:
    print(f'Duplicating submission {i} of {len(exportable)}')
    i += 1
    exported_id = sub['contest_id'] + '-' + sub['problem_id']
    if exported_id not in problem_ids:
        continue
    db.execute(('INSERT INTO submissions(date, user_id, problem_id, correct, submitted) '
                'VALUES(?, ?, ?, ?, ?)'), sub['date'], sub['user_id'], exported_id,
                sub['correct'], sub['submitted'])

print('Migration completed.')
