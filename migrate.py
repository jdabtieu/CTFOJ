import os
import cs50

db = cs50.SQL("sqlite:///database.db")
contests = db.execute("SELECT * FROM contests")

os.makedirs('metadata')
os.makedirs('metadata/problems')
os.makedirs('metadata/contests')
os.makedirs('metadata/announcements')
problems = db.execute("SELECT * FROM problems")
contests = db.execute("SELECT * FROM contests")
announcements = db.execute("SELECT * FROM announcements")

for problem in problems:
	pid = problem["id"]
	description = problem["description"]
	editorial = problem["editorial"]
	hints = problem["hints"]
	if description is None:
		description = ""
	if editorial is None:
		editorial = ""
	if hints is None:
		hints = ""
	os.makedirs('metadata/problems/' + pid)
	f = open('metadata/problems/' + pid + '/description.md', 'w')
	f.write(description)
	f.close()
	f = open('metadata/problems/' + pid + '/hints.md', 'w')
	f.write(hints)
	f.close()
	f = open('metadata/problems/' + pid + '/editorial.md', 'w')
	f.write(editorial)
	f.close()

db.execute("BEGIN")
db.execute("CREATE TABLE 'problems_tmp' ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0))")

for problem in problems:
	db.execute("INSERT INTO problems_tmp VALUES(?, ?, ?, ?, ?, ?)",
			   problem["id"], problem["name"], problem["point_value"],
			   problem["category"], problem["flag"], problem["draft"])

db.execute("DROP TABLE problems")
db.execute("ALTER TABLE problems_tmp RENAME TO problems")
db.execute("COMMIT")


for contest in contests:
	os.makedirs('metadata/contests/' + contest["id"])
	cid = contest["id"]

	cp = db.execute("SELECT * FROM :cidinfo", cidinfo=cid + "info")
	for problem in cp:
		pid = problem["id"]
		description = problem["description"]
		hints = problem["hints"]
		if description is None:
			description = ""
		if hints is None:
			hints = ""
		os.makedirs('metadata/contests/' + cid + '/' + pid)
		f = open('metadata/contests/' + cid + '/' + pid + '/description.md', 'w')
		f.write(description)
		f.close()
		f = open('metadata/contests/' + cid + '/' + pid + '/hints.md', 'w')
		f.write(hints)
		f.close()

	db.execute("BEGIN")
	db.execute("CREATE TABLE :cidtmp ('id' varchar(64) NOT NULL, 'name' varchar(256) NOT NULL, 'point_value' integer NOT NULL DEFAULT (0), 'category' varchar(64), 'flag' varchar(256) NOT NULL, 'draft' boolean NOT NULL DEFAULT(0))", cidtmp=cid + "info_tmp")

	for problem in cp:
		db.execute("INSERT INTO ? VALUES(?, ?, ?, ?, ?, ?)", cid + "info_tmp", 
				   problem["id"], problem["name"], problem["point_value"],
				   problem["category"], problem["flag"], problem["draft"])

	db.execute("DROP TABLE :cidinfo", cidinfo=cid + "info")
	db.execute("ALTER TABLE :cidtmp RENAME TO :cidinfo",
			   cidtmp=cid + "info_tmp", cidinfo=cid + "info")
	db.execute("COMMIT")


	description = contest["description"]
	f = open('metadata/contests/' + cid + '/description.md', 'w')
	f.write(description)
	f.close()

db.execute("BEGIN")
db.execute("CREATE TABLE 'contests_tmp' ('id' varchar(32) NOT NULL, 'name' varchar(256) NOT NULL, 'start' datetime NOT NULL, 'end' datetime NOT NULL, 'scoreboard_visible' boolean NOT NULL DEFAULT(1))")
for contest in contests:
	db.execute("INSERT INTO contests_tmp VALUES(?, ?, ?, ?, ?)",
			   contest["id"], contest["name"], contest["start"], contest["end"],
			   contest["scoreboard_visible"])

db.execute("DROP TABLE contests")
db.execute("ALTER TABLE contests_tmp RENAME TO contests")
db.execute("COMMIT")

for announcement in announcements:
	aid = announcement["id"]
	description = announcement["description"]
	if description is None:
		description = ""
	f = open('metadata/announcements/' + str(aid) + '.md', 'w')
	f.write(description)
	f.close()

db.execute("BEGIN")
db.execute("CREATE TABLE 'announcements_tmp' ('id' integer PRIMARY KEY NOT NULL, 'name' varchar(256) NOT NULL, 'date' datetime NOT NULL)")

for announcement in announcements:
	db.execute("INSERT INTO announcements_tmp VALUES(?, ?, ?)",
			   announcement["id"], announcement["name"], announcement["date"])

db.execute("DROP TABLE announcements")
db.execute("ALTER TABLE announcements_tmp RENAME TO announcements")
db.execute("COMMIT")