import json


def test_api(client, database):
    '''Test to ensure api functions.'''
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0, NULL)"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/api/getkey')
    assert database.execute("SELECT * FROM users")[0]["api"] == result.data.decode('utf-8')  # noqa

    result = client.get('/api')
    assert result.status_code == 308

    client.get('/logout')

    result = client.get('/api/problem?id=anything')
    assert result.status_code == 401
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)

    database.execute("UPDATE users SET api='00000000-0000-0000-0000-000000000000'")
    result = client.get('/api/contests?id=successful&key=00000000-0000-0000-0000-000000000000')
    assert result.status_code == 200
    assert json.loads(result.data)['status'] == 'success'
    assert 'data' in json.loads(result.data)
    assert 'message' not in json.loads(result.data)

    result = client.get('/api/nonexistent')
    assert result.status_code == 404
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)