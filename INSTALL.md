# Installation

Prerequisites: Python 3, SQLite 3

It is recommended to create a venv (virtual environment) first.

# Initial setup
The setup process involves 3 main steps:
1. Install dependencies
2. Create database
3. Configure application

&nbsp;
1.
```bash
$ pip3 install -r requirements.txt
```

2.
```sql
$ sqlite3 database.db
sqlite3>
CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0) , 'admin' boolean NOT NULL DEFAULT (0) , 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0));
CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, 'date' datetime NOT NULL,'user_id' integer NOT NULL,'problem_id' varchar(32) NOT NULL,'contest_id' varchar(32), 'correct' boolean NOT NULL);
CREATE TABLE 'problems_master' ('user_id' integer NOT NULL);
CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'description' varchar(16384), 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL , 'editorial' text, 'hints' varchar(16384), 'draft' boolean NOT NULL DEFAULT(0));
CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'description' text, 'scoreboard_visible' boolean NOT NULL DEFAULT (1));
CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL, 'description' varchar(16384) NOT NULL);
INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1);
INSERT INTO 'problems_master' ('user_id') VALUES(1);
```

3.
```bash
$ mkdir logs
$ touch logs/application.log
$ python3 daily_tasks.py
$ cp default_settings.py settings.py
$ nano settings.py
```
In settings.py, you should add your email credentials as indicated by default_settings.py. Additionally, you may change the other email settings if you do not use Gmail. Finally, you should add a custom name for your club and change any other settings that you wish to change.

# Running in Debug Mode
```
$ export FLASK_APP=application.py
$ flask run
```
If you do not want to export the FLASK_APP every time you reset your terminal, you can put it in your .bashrc or create a symbolic link.

Do not expose the app to the web using debug mode. You should run the app through nginx, Apache, or a similar service.

# Logging in for the first time
An admin account has been created in step 2. You can log in to it using the credentials `admin:CTFOJadmin`. Make sure you change your password immediately after logging in.
You should also change the admin email to your email so that you can reset your password in the future through the web app.
```sql
$ sqlite3 database.db
sqlite3> UPDATE 'users' SET email='YOUR EMAIL HERE' WHERE id=1;
```
Furthermore, when regular users log in for the first time, they will be directed to a helloworld problem. You should create a helloworld problem as a welcome/landing page. This problem must have an id of 'helloworld', without the single quotes. See below for an example helloworld problem:
```sql
$ sqlite3 database.db
sqlite3> INSERT INTO 'problems' VALUES('helloworld', 'Hello World', 'Welcome to CTF Club! In each problem, you must find a flag hidden somewhere on the problem page.', 1, 'general', 'CTF{your_first_ctf_flag}', 'The flag starts with CTF{', 'The flag ends with }', 0);
```
