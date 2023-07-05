import json
import os
import shutil

from datetime import datetime
from datetime import timedelta


def test_dl(client, database):
    """
    Test permission with downloading challenge attachments
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0, '00000000-0000-0000-0000-000000000000', 0, 0, 0)"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    result = client.post('/contests/create', data={
        'contest_id': 'testingcontest',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now() + timedelta(400), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 200

    file = open("test_upload.zip", "w")
    file.write('ree')
    file.close()
    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'draft': True,
        'file': ('test_upload.zip', 'test_upload.zip')
    })
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'helloworldtesting2',
        'name': 'hello world2',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'file': ('test_upload.zip', 'test_upload.zip')
    })
    assert result.status_code == 302

    result = client.post('/problems/create', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'instanced': True,
        'file': ('test_upload.zip', 'test_upload.zip'),
        'draft': True
    })
    assert result.status_code == 302
    os.remove('test_upload.zip')

    # Admins should see downloads of future contests and draft problems
    result = client.get('/dl/testingcontest/helloworldtesting.zip')
    assert result.status_code == 200

    result = client.get('/dl/testingcontest/helloworldtesting2.zip')
    assert result.status_code == 200

    result = client.get('/dl/helloworldtesting.zip')
    assert result.status_code == 200

    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 0, 1, 0, '00000000-0000-0000-0000-000000000001', 0, 0, 0)"))
    client.post('/login', data={'username': 'normal_user', 'password': 'CTFOJadmin'})

    # Users should not see downloads of future contests and draft problems
    result = client.get('/dl/testingcontest/helloworldtesting.zip')
    assert result.status_code == 404

    result = client.get('/dl/testingcontest/helloworldtesting2.zip')
    assert result.status_code == 404

    result = client.get('/dl/helloworldtesting.zip')
    assert result.status_code == 404

    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/contest/testingcontest/edit', data={
        'name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(60), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 200

    result = client.post('/problem/helloworldtesting/publish', follow_redirects=True)
    assert result.status_code == 200

    client.post('/login', data={'username': 'normal_user', 'password': 'CTFOJadmin'})

    # Users should see downloads of current contests but not draft problems
    result = client.get('/dl/testingcontest/helloworldtesting.zip')
    assert result.status_code == 404

    print(database.execute("SELECT * FROM contest_problems"))

    result = client.get('/dl/testingcontest/helloworldtesting2.zip')
    assert result.status_code == 200

    result = client.get('/dl/helloworldtesting.zip')
    assert result.status_code == 200

    # Cleanup
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/problem/helloworldtesting/delete', follow_redirects=True)
    assert result.status_code == 200