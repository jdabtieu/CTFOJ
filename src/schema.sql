CREATE TABLE 'users' (
    'id' integer PRIMARY KEY NOT NULL,
    'username' varchar(20) NOT NULL UNIQUE,
    'password' varchar(64) NOT NULL,
    'email' varchar(128) UNIQUE,
    'join_date' datetime NOT NULL DEFAULT(0),
    'banned' boolean NOT NULL DEFAULT(0),
    'verified' boolean NOT NULL DEFAULT(0),
    'twofa' boolean NOT NULL DEFAULT(0),
    'api' varchar(36) UNIQUE,
    'total_points' integer NOT NULL DEFAULT(0),
    'contests_completed' integer NOT NULL DEFAULT(0),
    'problems_solved' integer NOT NULL DEFAULT(0)
);
CREATE TABLE 'user_perms' (
    'user_id' integer NOT NULL,
    'perm_id' integer NOT NULL,
    UNIQUE(perm_id, user_id) ON CONFLICT IGNORE
);
CREATE TABLE 'submissions' (
    'id' integer PRIMARY KEY NOT NULL,
    'date' datetime NOT NULL DEFAULT(datetime('now')),
    'user_id' integer NOT NULL,
    'problem_id' varchar(32) NOT NULL,
    'contest_id' varchar(32),
    'correct' boolean NOT NULL,
    'submitted' text NOT NULL DEFAULT('')
);
CREATE TABLE 'problems' (
    'id' varchar(64) NOT NULL UNIQUE,
    'name' varchar(256) NOT NULL,
    'point_value' integer NOT NULL DEFAULT(0),
    'category' varchar(64),
    'flag' varchar(256) NOT NULL,
    'status' integer NOT NULL DEFAULT(0), -- see helpers.py
    'flag_hint' varchar(256) NOT NULL DEFAULT(''),
    'instanced' boolean NOT NULL DEFAULT(0)
);
CREATE TABLE 'problem_solved' (
    'user_id' integer NOT NULL,
    'problem_id' varchar(64) NOT NULL,
    UNIQUE(problem_id, user_id) ON CONFLICT ABORT
);
CREATE TABLE 'contests' (
    'id' varchar(32) NOT NULL UNIQUE,
    'name' varchar(256) NOT NULL,
    'start' datetime NOT NULL,
    'end' datetime NOT NULL,
    'scoreboard_visible' boolean NOT NULL DEFAULT(1),
    'scoreboard_key' varchar(36)
);
CREATE TABLE 'announcements' (
    'id' integer PRIMARY KEY NOT NULL,
    'name' varchar(256) NOT NULL,
    'date' datetime NOT NULL
);
CREATE TABLE 'contest_users' (
    'contest_id' varchar(32) NOT NULL,
    'user_id' integer NOT NULL,
    'points' integer NOT NULL DEFAULT (0),
    'lastAC' datetime,
    'hidden' integer NOT NULL DEFAULT(0), -- 1: hidden, 2: banned
    UNIQUE(contest_id, user_id) ON CONFLICT ABORT
);
CREATE TABLE 'contest_solved' (
    'contest_id' varchar(32) NOT NULL,
    'user_id' integer NOT NULL,
    'problem_id' varchar(64) NOT NULL,
    UNIQUE(contest_id, user_id, problem_id) ON CONFLICT ABORT
);
CREATE TABLE 'contest_problems' (
    'contest_id' varchar(32) NOT NULL,
    'problem_id' varchar(64) NOT NULL,
    'name' varchar(256) NOT NULL,
    'point_value' integer NOT NULL DEFAULT(0),
    'category' varchar(64),
    'flag' varchar(256) NOT NULL,
    'status' integer NOT NULL DEFAULT(0), -- 0: published, 1: draft
    'score_min' integer NOT NULL DEFAULT(0),
    'score_max' integer NOT NULL DEFAULT(0),
    'score_users' integer NOT NULL DEFAULT(-1),
    'flag_hint' varchar(256) NOT NULL DEFAULT(''),
    'instanced' boolean NOT NULL DEFAULT(0),
    UNIQUE(contest_id, problem_id) ON CONFLICT ABORT
);
