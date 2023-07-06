from pathlib import Path
import pytest

from cs50 import SQL


Path("logs").mkdir(parents=True, exist_ok=True)
Path("dl").mkdir(parents=True, exist_ok=True)
Path("metadata").mkdir(parents=True, exist_ok=True)
Path("metadata/contests").mkdir(parents=True, exist_ok=True)
Path("metadata/problems").mkdir(parents=True, exist_ok=True)
Path("metadata/announcements").mkdir(parents=True, exist_ok=True)
Path("backups").mkdir(parents=True, exist_ok=True)
with open("secret_key.txt", "w") as file:
    file.write("testing_secret_key")

from application import app  # noqa


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['USE_CAPTCHA'] = False
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SECRET_KEY'] = 'testing_secret_key'
    return app.test_client()


@pytest.fixture
def database():
    open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")
    db.execute(
        ("CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, "
         "'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, "
         "'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0), "
         "'admin' boolean NOT NULL DEFAULT (0), 'banned' boolean NOT NULL DEFAULT (0), "
         "'verified' boolean NOT NULL DEFAULT (0), 'twofa' boolean NOT NULL DEFAULT (0), "
         "'api' varchar(36), 'total_points' integer NOT NULL DEFAULT(0), "
         "'contests_completed' integer NOT NULL DEFAULT(0), "
         "'problems_solved' integer NOT NULL DEFAULT(0))"))
    db.execute(
        ("CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, "
         "'date' datetime NOT NULL, 'user_id' integer NOT NULL, "
         "'problem_id' varchar(32) NOT NULL, 'contest_id' varchar(32), "
         "'correct' boolean NOT NULL, 'submitted' text NOT NULL DEFAULT(''))"))
    db.execute(
        ("CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, "
         "'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), "
         "'category' varchar(64), 'flag' varchar(256) NOT NULL, "
         "'draft' boolean NOT NULL DEFAULT(0), "
         "'flag_hint' varchar(256) NOT NULL DEFAULT(''), "
         "'instanced' boolean NOT NULL DEFAULT(0))"))
    db.execute(
        ("CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, "
         "'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, "
         "'end' datetime NOT NULL, 'scoreboard_visible' boolean NOT NULL DEFAULT (1), "
         "'scoreboard_key' varchar(36))"))
    db.execute(
        ("CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, "
         "'name' varchar(256) NOT NULL, 'date' datetime NOT NULL)"))
    db.execute(
        ("CREATE TABLE 'contest_users' ('contest_id' varchar(32) NOT NULL, "
         "'user_id' integer NOT NULL, 'points' integer NOT NULL DEFAULT(0), "
         "'lastAC' datetime, 'hidden' integer NOT NULL DEFAULT(0))"))
    db.execute(
        ("CREATE TABLE 'contest_solved' ('contest_id' varchar(32) NOT NULL, "
         "'user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL)"))
    db.execute(
        ("CREATE TABLE 'contest_problems' ('contest_id' varchar(32) NOT NULL, "
         "'problem_id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, "
         "'point_value' integer NOT NULL DEFAULT(0), 'category' varchar(64), "
         "'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0), "
         "'score_min' integer NOT NULL DEFAULT(0), "
         "'score_max' integer NOT NULL DEFAULT(0), "
         "'score_users' integer NOT NULL DEFAULT(-1), "
         "'flag_hint' varchar(256) NOT NULL DEFAULT(''), "
         "'instanced' boolean NOT NULL DEFAULT(0))"))
    db.execute(
        ("CREATE TABLE 'problem_solved' ('user_id' integer NOT NULL, "
         "'problem_id' varchar(64) NOT NULL)"))
    return db
