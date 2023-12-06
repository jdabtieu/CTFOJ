from cs50 import SQL as cs50_SQL
import sys

class SQL:
    def __init__(self, url, **kwargs):
        self.db = cs50_SQL(url, **kwargs)

    def execute(self, query, *args, **kwargs):
        try:
            return self.db.execute(query, *args, **kwargs)
        except ValueError as e:
            if self.db._autocommit:
                self.db._autocommit = False
                self.db.execute("ROLLBACK")
            raise e



try:
    db = SQL("sqlite:///database.db")
except Exception as e:  # when testing
    sys.stderr.write(str(e))
    open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")
