import json

def test_login(client, database):
    '''Test the login interface with pre-added account.'''
    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1);")
    result = client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin'})
    assert result.status_code == 302

    logged_in = client.get('/')
    assert logged_in.status_code == 200
    assert b'Welcome' in logged_in.data
