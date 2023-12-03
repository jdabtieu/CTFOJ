import hashlib
import json


def sha256sum(string):
    return hashlib.sha256(string.encode("utf-8")).hexdigest()


def test_api(client, database):
    '''Test to ensure api functions.'''
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    client.post('/login', data={'username': 'user', 'password': 'CTFOJadmin'})
    result = client.post('/api/getkey')
    assert (database.execute("SELECT * FROM users")[0]["api"]
            == hashlib.sha256(result.data).hexdigest())

    result = client.get('/api')
    assert result.status_code == 308

    result = client.get('/api/problem')
    assert result.status_code == 400
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)

    result = client.get('/api/contests')
    assert result.status_code == 400
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)

    result = client.get('/api/problem?id=noexist')
    assert result.status_code == 404
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)

    client.get('/logout')

    result = client.get('/api/problem?id=anything')
    assert result.status_code == 401
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)

    database.execute("UPDATE users SET api=?", sha256sum('00000000-0000-0000-0000-000000000000'))  # noqa
    result = client.get('/api/contests?id=successful&key=00000000-0000-0000-0000-000000000000')  # noqa
    assert result.status_code == 200
    assert json.loads(result.data)['status'] == 'success'
    assert 'data' in json.loads(result.data)
    assert 'message' not in json.loads(result.data)

    result = client.get('/api/nonexistent')
    assert result.status_code == 404
    assert json.loads(result.data)['status'] == 'fail'
    assert 'data' not in json.loads(result.data)
    assert 'message' in json.loads(result.data)
