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
    open('fake_empty_file', 'w').close()
    return app.test_client()


@pytest.fixture
def database():
    open("database_test.db", "w").close()
    db = SQL("sqlite:///database_test.db")
    with open("schema.sql") as schemafile:
        schema = schemafile.read().split(";")  # split commands by ;
        schema = [x.strip() for x in schema]  # strip newlines
        schema = [x for x in schema if x]  # remove empty commands
    for query in schema:
        db.execute(query)
    return db
