# Bash script for running tests on Windows
# Running tests in your working directory will delete your database! Avoid this!
# WARNING: Make sure you are not already using the /tmp/CTFOJ folder!
# This should be run using Git Bash on Windows by executing ./wintest.sh in the tests directory
# Alternatively, you can test manually however you like.

# Checkout repo
echo 'Checking out working directory into /tmp/CTFOJ...'
cp -r .. /tmp/CTFOJ
echo 'Checking out working directory into /tmp/CTFOJ...Done!'

# Generate secret key (otherwise application.py will throw an error)
cd /tmp/CTFOJ
rm -rf logs dl metadata secret_key.txt database.db settings.py database.db.bak
python daily_tasks.py

# Run tests
echo 'Running tests...'
python -m pytest -v
echo 'Running tests...Done!'

# Cleanup
cd /tmp
rm -rf CTFOJ
echo 'Cleanup done!'
