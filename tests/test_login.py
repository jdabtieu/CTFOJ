def test_login(client, database):
    '''Test the login interface with pre-added account.'''
    result = client.get('/login')
    assert result.status_code == 200
    assert b'Log In' in result.data

    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1);")
    result = client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin'}, follow_redirects = True)
    assert result.status_code == 200
    assert b'Welcome' in result.data

    result = client.get('/logout', follow_redirects=True)
    assert result.status_code == 200
    assert b'Log In' in result.data

    '''Test the next parameter.'''
    result = client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin', 'next': '/admin/submissions'}, follow_redirects = True)
    assert result.status_code == 200
    assert b'Submissions' in result.data

    '''Test login errors.'''
    result = client.post('/login', data = {'username': 'noexist', 'password': 'CTFOJadmin'}, follow_redirects = True)
    assert result.status_code == 401
    assert b'Incorrect username/password' in result.data

    result = client.post('/login', data = {'username': 'admin', 'password': 'nopasswd'}, follow_redirects = True)
    assert result.status_code == 401
    assert b'Incorrect username/password' in result.data

    database.execute("INSERT INTO 'users' VALUES(2, 'user', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 1, 1);")
    result = client.post('/login', data = {'username': 'user', 'password': 'CTFOJadmin'}, follow_redirects = True)
    assert result.status_code == 403
    assert b'banned' in result.data

    database.execute("INSERT INTO 'users' VALUES(3, 'user2', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 0, 0);")
    result = client.post('/login', data = {'username': 'user2', 'password': 'CTFOJadmin'}, follow_redirects = True)
    assert result.status_code == 403
    assert b'not confirmed' in result.data
