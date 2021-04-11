import os
import shutil


def test_problem(client, database):
    """
    Test that admins can create problems, users can submit to them, and
    flags can be validated successfully.
    """
    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1, 0);")
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    file = open("test_upload.txt", "w")
    file.write('ree')
    file.close()
    result = client.post('/admin/createproblem', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hint': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'file': ('test_upload.txt', 'test_upload.txt'),
        'draft': True
    })
    os.remove('test_upload.txt')
    assert result.status_code == 302

    result = client.post('/problem/helloworldtesting/publish', follow_redirects=True)
    assert result.status_code == 200
    assert b'published' in result.data

    result = client.post('/problem/helloworldtesting/editeditorial',
                         data={'editorial': 'sample editorial'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'edited' in result.data

    result = client.post('/problem/helloworldtesting/edit', data={
        'name': 'hello world 2',
        'description': 'a short fun problem 2',
        'hint': 'try looking at the title 2',
        'point_value': 2,
        'category': 'web',
        'flag': 'ctf{hello}'
    })
    assert result.status_code == 302
    client.get('/logout')

    # test if normal users can view the problem
    database.execute("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 0, 1, 0)")
    client.post('/login', data={'username': 'normal_user', 'password': 'CTFOJadmin'},
                follow_redirects=True)
    result = client.get('/problem/helloworldtesting')
    assert result.status_code == 200
    assert b'a short fun problem' in result.data

    result = client.get('/problem/helloworldtesting/editorial')
    assert result.status_code == 200
    assert b'sample editorial' in result.data

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
    result = client.post('/problem/helloworldtesting/delete', follow_redirects=True)
    assert result.status_code == 200
    assert b'helloworldtesting' not in result.data

    shutil.rmtree('dl')
    os.mkdir('dl')
