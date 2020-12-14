import os
import pytest

from cs50 import SQL

from application import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['USE_CAPTCHA'] = False
    app.config['WTF_CSRF_ENABLED'] = False
    return app.test_client()

@pytest.fixture
def database():
    os.remove("database_test.db")
    open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")
    db.execute("CREATE TABLE 'users' ('id' integer PRIMARY KEY NOT NULL, 'username' varchar(20) NOT NULL, 'password' varchar(64) NOT NULL, 'email' varchar(128), 'join_date' datetime NOT NULL DEFAULT (0), 'admin' boolean NOT NULL DEFAULT (0), 'banned' boolean NOT NULL DEFAULT (0), 'verified' boolean NOT NULL DEFAULT (0), 'twofa' boolean NOT NULL DEFAULT (0));")
    db.execute("CREATE TABLE 'submissions' ('sub_id' integer PRIMARY KEY NOT NULL, 'date' datetime NOT NULL,'user_id' integer NOT NULL,'problem_id' varchar(32) NOT NULL,'contest_id' varchar(32), 'correct' boolean NOT NULL);")
    db.execute("CREATE TABLE 'problems' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0));")
    db.execute("CREATE TABLE 'contests' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'scoreboard_visible' boolean NOT NULL DEFAULT (1));")
    db.execute("CREATE TABLE 'announcements' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL);")
    db.execute("CREATE TABLE 'contest_users' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'points' integer NOT NULL DEFAULT(0), 'lastAC' datetime);")
    db.execute("CREATE TABLE 'contest_solved' ('contest_id' varchar(32) NOT NULL, 'user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);")
    db.execute("CREATE TABLE 'contest_problems' ('contest_id' varchar(32) NOT NULL, 'problem_id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT(0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0));")
    db.execute("CREATE TABLE 'problem_solved' ('user_id' integer NOT NULL, 'problem_id' varchar(64) NOT NULL);")
    return db
