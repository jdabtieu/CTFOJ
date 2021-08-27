#!/bin/bash

echo "Starting precheck..."
PYTH=$(which python3)
PYTHPIP=$(which pip3)
python3 --version
if [[ $? != 0 ]]; then
    python --version
    if [[ $? != 0 ]]; then
        echo "Python 3 not installed. Make sure you have Python 3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    fi
    if [[ $(python --version | grep "Python 3" | wc -c) -eq 0 ]]; then
        echo "Python 3 not installed. Make sure you have Python 3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    else
        pip --version
        if [[ $? != 0 ]]; then
            echo "pip not installed. Make sure you have pip installed and available in PATH."
            echo "**STOPPING**"
            exit 1
        fi
        PYTH=$(which python)
        PYTHPIP=$(which pip)
    fi
else
    pip3 --version
    if [[ $? != 0 ]]; then
        echo "pip3 not installed. Make sure you have pip3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    fi
fi

if [[ $(which sqlite3 | wc -c) -eq 0 ]]; then
    echo "sqlite3 not installed. Make sure it is installed and available in PATH."
    echo "**STOPPING**"
    exit 1
fi
if [[ $(which nano | wc -c) -eq 0 ]]; then
    echo "nano not installed. Make sure it is installed and available in PATH."
    echo "**STOPPING**"
    exit 1
fi
"$PYTH" -m venv .
if [[ $? != 0 ]]; then
    echo "venv creation failed. Make sure you have Python 3 and the virtualenv package installed."
    echo "**STOPPING**"
    exit 1
fi
echo "Precheck complate!"
. bin/activate || . Scripts/activate
cd src
echo "Installing dependencies..."
"$PYTHPIP" install wheel
"$PYTHPIP" install -r requirements.txt
echo "Creating database..."
sqlite3 database.db << EOF
CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0), 'admin' boolean NOT NULL DEFAULT (0), 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0), 'twofa' boolean NOT NULL DEFAULT (0), 'api' varchar(36));
CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, 'date' datetime NOT NULL,'user_id' integer NOT NULL,'problem_id' varchar(32) NOT NULL,'contest_id' varchar(32), 'correct' boolean NOT NULL, 'submitted' text NOT NULL DEFAULT(''));
CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0));
CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'scoreboard_visible' boolean NOT NULL DEFAULT (1));
CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL);
CREATE TABLE 'contest_users' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'points' integer NOT NULL DEFAULT (0) , 'lastAC' datetime);
CREATE TABLE 'contest_solved' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);
CREATE TABLE 'contest_problems' ('contest_id' varchar(32) NOT NULL, 'problem_id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT(0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0), 'score_min' integer NOT NULL DEFAULT(0), 'score_max' integer NOT NULL DEFAULT(0), 'score_users' integer NOT NULL DEFAULT(-1));
CREATE TABLE 'problem_solved' ('user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);
INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000\$XoLKRd3I\$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1, 0, NULL);
EOF
echo "Finishing setup..."
mkdir logs dl metadata metadata/contests metadata/problems metadata/announcements
chmod +x daily_tasks.py
"$PYTH" daily_tasks.py
cp default_settings.py settings.py
cp templates/default_homepage.html metadata/homepage.html
echo "Configuring settings..."
echo "Admin Email: "
read ADMIN_EMAIL
sqlite3 database.db << EOF
UPDATE 'users' SET email='$ADMIN_EMAIL' WHERE id=1;
EOF
nano settings.py
echo "Success! CTFOJ is now set up."
echo "Running application as debug... You may exit anytime by hitting Ctrl+C"
"$PYTH" application.py
deactivate
