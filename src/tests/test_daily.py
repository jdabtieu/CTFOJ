import os

open('database.db', 'a').close()
open('logs/application.log', 'a').close()

import daily_tasks  # noqa


def test_daily(client):
    """
    Test if daily_tasks.py runs properly and users aren't able to access the secret files.
    """
    assert os.path.exists('secret_key.txt')
    assert os.path.exists('database.db.bak')

    result = client.get('/logs/application.log')
    assert result.status_code == 404
    result = client.get('/secret_key.txt')
    assert result.status_code == 404
    result = client.get('/database.db')
    assert result.status_code == 404
    result = client.get('/database.db.bak')
    assert result.status_code == 404


os.remove('database.db')
