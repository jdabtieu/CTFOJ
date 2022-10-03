# Installation
Prerequisites: Python 3, SQLite 3

For updating instructions, click [here](#updating).

Although CTFOJ can run on Linux, Windows, and MacOS, it is recommended to run it
on a modern Linux distribution such as Ubuntu 22.04 LTS. This guide assumes that
you are running Linux.

# Step 0 - Getting a copy of CTFOJ
The best way to get a copy of CTFOJ is to clone the repository at the version
you want. It is recommended to use the latest stable release, whose version
number can be found [here](https://github.com/jdabtieu/CTFOJ/releases). For
example, to get version v2.4.3, run
```bash
$ git clone --depth 1 --branch v2.4.3 https://github.com/jdabtieu/CTFOJ.git
$ cd CTFOJ
```

# Installation Instructions
It is recommended to use the provided INSTALL.sh script if you are have bash
available (Linux/MacOS based, msys, etc.). If you wish to install manually,
or are using another operating system, please keep reading.If you use the
INSTALL.sh script, skip to
[Logging in for the first time](#step-6---logging-in-for-the-first-time)

## Manual Installation
### Step 1 - Setting up the environment
We'll need to create a virtualenv to isolate CTFOJ's dependencies from the rest
of your system. Navigate to the CTFOJ root folder through your terminal of
choice, and then type the following command:
```bash
$ python3 -m venv .
$ . bin/activate
```

### Step 2 - Installing Dependencies
We'll now install the dependencies that CTFOJ relies on.
```bash
$ cd src
$ pip3 install -r requirements.txt
```

### Step 3 - Setting up the database
We'll now set up the database and create the required tables for CTFOJ to work.
```sql
$ sqlite3 database.db
sqlite3>
CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0), 'admin' boolean NOT NULL DEFAULT (0), 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0), 'twofa' boolean NOT NULL DEFAULT (0), 'api' varchar(36));
CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, 'date' datetime NOT NULL,'user_id' integer NOT NULL,'problem_id' varchar(32) NOT NULL,'contest_id' varchar(32), 'correct' boolean NOT NULL, 'submitted' text NOT NULL DEFAULT(''));
CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0));
CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'scoreboard_visible' boolean NOT NULL DEFAULT (1));
CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL);
CREATE TABLE 'contest_users' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'points' integer NOT NULL DEFAULT (0) , 'lastAC' datetime, 'hidden' NOT NULL DEFAULT(0));
CREATE TABLE 'contest_solved' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);
CREATE TABLE 'contest_problems' ('contest_id' varchar(32) NOT NULL, 'problem_id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT(0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0), 'score_min' integer NOT NULL DEFAULT(0), 'score_max' integer NOT NULL DEFAULT(0), 'score_users' integer NOT NULL DEFAULT(-1), 'flag_hint' varchar(256) NOT NULL DEFAULT(''));
CREATE TABLE 'problem_solved' ('user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);
INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1, 0, NULL);
```

### Step 4 - Configuring the filesystem and configuration
CTFOJ also relies on certain folders - for example, the metadata folder to store
problem statements. We'll be creating them now.
```bash
$ mkdir logs dl metadata metadata/contests metadata/problems metadata/announcements
$ chmod +x daily_tasks.py
$ python3 daily_tasks.py
$ cp default_settings.py settings.py
$ cp templates/default_homepage.html metadata/homepage.html
$ nano settings.py
```
In settings.py, you should add your email credentials as indicated by
default_settings.py. **If you are using Gmail, use an app password instead of
your account password. For more info, see
[here](https://support.google.com/accounts/answer/185833).**
Next, you should choose whether to use a CAPTCHA or not, and add your hCaptcha
site and secret keys if you are using a CAPTCHA. After that, you should add a
custom name for your club and change any other settings that you wish to change.
Finally, you should choose whether to enable a homepage. If you decide to do so,
make sure to specify the location of the homepage.

Then, you should change the admin email manually so that you can reset your
password in the future through the CTFOJ app.
```sql
$ sqlite3 database.db
sqlite3> UPDATE 'users' SET email='YOUR EMAIL HERE' WHERE id=1;
```

### Step 5 - Running in Debug Mode
To run the application in debug mode, you can use the following command. Note
that you should never expose the app to the web using debug mode. You should run
the app through a WSGI application, such as Gunicorn or uWSGI.
```bash
$ python3 application.py
```

### Step 6 - Logging in for the first time
An admin account has been created in step 2. You can log in to it using the
credentials `admin:CTFOJadmin`. Make sure you change your password immediately
after logging in. Enabling 2FA is also recommended for the admin account. You
can change your password and enable 2FA through the settings page.

Furthermore, when regular users log in for the first time, they will be directed
to a helloworld problem. You should create a helloworld problem as a
welcome/landing page. This problem must have an id of 'helloworld', without the
single quotes. You can do this on the 'Create Problem' page in the admin
toolbar, once logged in. Markdown is supported. See below for an example
helloworld problem:
```
**Welcome to CTF Club!** In each problem, you must find a flag hidden somewhere on the problem page.

The flag for this problem is: `CTF{your_first_ctf_flag}`
```

# Optional Steps
You may optionally replace the default favicon.png file in the static folder
with another icon of your choice (must be named favicon.png). This icon will be
displayed in the title bar of a CTFOJ tab in users' web browsers.

`daily_tasks.py` creates automatic backups of the database and splits logs by
date. To set it up, use your task scheduler to run it once per day, in the src
directory. For example, for cron, you can use:
```cron
0 0 * * * cd /path/to/install/CTFOJ/src && python3 daily_tasks.py
```
Make sure you replace `/path/to/install` with your CTFOJ installation path.

# Updating
To update, first fetch the latest changes from GitHub. This can be done with:
```bash
$ git pull
```

Then, revert to the version you are looking for. This can be done with:
```bash
$ git reset --hard [version number]
```
The version number should look like v#.#.#. An example is v2.1.0. Assuming all
goes well, you should see a message like
```
HEAD is now at ###### Some message here
```

Finally, you'll want to restart your WSGI application to apply the changes.
The command will vary depending on your WSGI application.
