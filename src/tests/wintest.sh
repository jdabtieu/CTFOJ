# Bash script for running tests on Windows
# Running tests in your working directory will delete your database! Avoid this!
# This should be run using Git Bash on Windows by executing ./wintest.sh
# Alternatively, you can test manually however you like.

# Checkout repo
cd /tmp
echo 'Checking out CTFOJ into /tmp...'
git clone https://github.com/jdabtieu/CTFOJ.git --depth 1 -q
echo 'Checking out CTFOJ into /tmp...Done!'

# Generate secret key (otherwise application.py will throw an error)
cd CTFOJ/src
python daily_tasks.py

# Run tests
echo 'Running tests...'
python -m pytest -v
echo 'Running tests...Done!'

# Cleanup
cd ../..
rm -rf CTFOJ
echo 'Cleanup done!'
