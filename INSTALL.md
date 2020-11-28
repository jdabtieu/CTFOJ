Prerequisites: Python 3, SQLite 3

It is recommended to create a venv (virtual environment) first.

# First time setup
The setup process involves 3 main steps:
1. Install dependencies
2. Create database
3. Configure application

&nbsp;
1.
```
$ pip3 install -r requirements.txt
```

2.
```
$ sqlite3 database.db
sqlite3>
CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0) , 'admin' boolean NOT NULL DEFAULT (0) , 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0));
CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, 'date' datetime NOT NULL,'user_id' integer NOT NULL,'problem_id' varchar(32) NOT NULL,'contest_id' varchar(32), 'correct' boolean NOT NULL);
CREATE TABLE 'problems_master' ('user_id' integer NOT NULL);
CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'description' varchar(16384), 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL , 'editorial' text, 'hints' varchar(16384));
CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'description' text, 'scoreboard_visible' boolean NOT NULL DEFAULT (1));
CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL, 'description' varchar(16384) NOT NULL);
```

3.
```
$ cp default_settings.py settings.py
$ nano settings.py # add your email credentials
$ python3 daily-tasks.py
```

# Running
```
$ export FLASK_APP=application.py
$ flask run
```
If you do not want to export the FLASK_APP every time you reset your terminal, you can put it in your .bashrc or create a symbolic link.


At this time, it is recommended to sign up for an account and then give it administrator access
```
$ sqlite3 database.db
sqlite3> UPDATE users SET admin=1 WHERE username='username';
```
