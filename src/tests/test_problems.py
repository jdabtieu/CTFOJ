import json
import os
import shutil

from helpers import USER_PERM


def test_problem(client, database):
    """
    Test that admins can create problems, users can submit to them, and
    flags can be validated successfully.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, 1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    file = open("test_upload.txt", "w")
    file.write('ree')
    file.close()
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
        'file': ('test_upload.txt', 'test_upload.txt'),
        'draft': True
    })
    assert result.status_code == 302

    # TODO Assert the instancer interface exists

    result = client.post('/problem/helloworldtesting',
                         data={'flag': 'ctf{hello}'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'Congratulations' in result.data

    result = client.get('/users/admin/profile')
    assert result.status_code == 200
    assert b'1 Point' in result.data

    result = client.post('/problem/helloworldtesting/publish', follow_redirects=True)
    assert result.status_code == 200
    assert b'published' in result.data

    result = client.post('/problem/helloworldtesting/editeditorial',
                         data={'editorial': 'sample editorial'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'edited' in result.data

    result = client.post('/problem/helloworldtesting/edit', data={
        'description': 'a short fun problem 2',
        'hints': 'try looking at the title 2',
        'point_value': 2,
        'rejudge': True,
        'category': 'web',
        'flag': 'ctf{hello}',
        'file': ('fake_empty_file', ''),
    })
    assert result.status_code == 400
    assert b'required' in result.data

    result = client.post('/problem/helloworldtesting/edit', data={
        'name': 'hello world 2',
        'description': 'a short fun problem 2',
        'hints': 'try looking at the title 2',
        'point_value': 2,
        'rejudge': True,
        'category': 'web',
        'flag': '\x2f\x10',
        'file': ('fake_empty_file', ''),
    })
    assert result.status_code == 400
    assert b'Invalid' in result.data

    file = open("test_upload.txt", "w")
    file.write('ree2')
    file.close()
    result = client.post('/problem/helloworldtesting/edit', data={
        'name': 'hello world 2',
        'description': 'a short fun problem 2',
        'hints': 'try looking at the title 2',
        'point_value': 2,
        'rejudge': True,
        'category': 'web',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'file': ('test_upload.txt', 'test_upload.txt'),
    }, follow_redirects=True)
    assert result.status_code == 200

    result = client.get('/dl/helloworldtesting.zip')
    assert result.data == b'ree2'

    result = client.get('/users/admin/profile')
    assert result.status_code == 200
    assert b'2 Points' in result.data

    client.get('/logout')

    # make sure api_login_required is working properly
    result = client.get('/api/problem?id=helloworldtesting')
    assert result.status_code == 401

    # test if normal users can view the problem
    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    client.post('/login', data={'username': 'normal_user', 'password': 'CTFOJadmin'},
                follow_redirects=True)
    result = client.get('/problem/helloworldtesting')
    assert result.status_code == 200

    result = client.get('/api/problem?id=helloworldtesting')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['description'].startswith('a short fun problem 2')
    assert json.loads(result.data)['data']['hints'] == 'try looking at the title 2'
    assert json.loads(result.data)['data']['editorial'] == 'sample editorial'
    assert json.loads(result.data)['data']['flag_hint'] == 'ctf{...}'

    result = client.get('/problem/helloworldtesting/editorial')
    assert result.status_code == 200

    # test if normal users can submit to the problem
    result = client.post('/problem/helloworldtesting',
                         data={'flag': 'ctf{hello}'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'Congratulations' in result.data

    # test if nonexistent problems don't exist
    result = client.get('/problem/idontexist', follow_redirects=True)
    assert result.status_code == 404
    assert b'does not exist' in result.data
    client.get('/logout')

    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.get('/problem/helloworldtesting/download', follow_redirects=True)
    assert result.status_code == 200

    result = client.post('/problem/helloworldtesting/delete', follow_redirects=True)
    assert result.status_code == 200
    assert b'helloworldtesting' not in result.data

    shutil.rmtree('dl')
    os.mkdir('dl')
