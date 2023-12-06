# Bash script for running tests on Windows
# Running tests in your working directory will delete your database! Avoid this!
# WARNING: Make sure you are not already using the /tmp/CTFOJ_test folder!
# This should be run using Git Bash on Windows by executing ./wintest.sh in the tests directory
# Alternatively, you can test manually however you like.

# Prechecks
if [[ $(ls | grep wintest.sh | wc -c) -eq 0 ]]; then
    echo "Make sure you run wintest.sh in the tests directory."
    echo "**STOPPING**"
    exit 1
fi
ls /tmp/CTFOJ_test 2>/dev/null
if [[ $? -eq 0 ]]; then
    echo "/tmp/CTFOJ directory exists! Delete it for this test to run."
    echo "**STOPPING**"
    exit 1
fi

# Checkout repo
echo 'Checking out working directory into /tmp/CTFOJ_test...'
echo 'If cp whines about cannot create symbolic link, ignore it, it is ok'
cp -r .. /tmp/CTFOJ_test
echo 'Checking out working directory into /tmp/CTFOJ_test...Done!'

echo 'Setting up test environment...'
cd /tmp/CTFOJ_test
rm -rf logs dl metadata backups session secret_key.txt database.db settings.py
echo 'Setting up test environment...Done!'

# Run tests
echo 'Running tests...'
python -m pytest -v tests
echo 'Running tests...Done!'

# Cleanup
cd /tmp
rm -rf CTFOJ_test
echo 'Cleanup done!'
