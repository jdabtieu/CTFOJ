def test_maintenance(client, database):
    '''Test the maintenance mode.'''
    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1);")
    client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin'}, follow_redirects = True)

    result = client.get('/admin/maintenance', follow_redirects=True)
    assert result.status_code == 200
    assert b'Enabled' in result.data

    result = client.get('/', follow_redirects=True)
    assert result.status_code == 200
    assert b'maintenance' not in result.data

    result = client.get('/admin/maintenance', follow_redirects=True)
    assert result.status_code == 200
    assert b'Disabled' in result.data

    """
    result = client.get('/admin/maintenance', follow_redirects=True)

    result = client.get('/logout', follow_redirects = True)
    assert result.status_code == 503
    assert b'maintenance' in result.data

    result = client.get('/', follow_redirects = True)
    assert result.status_code == 503
    assert b'maintenance' in result.data

    client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin'}, follow_redirects = True)
    result = client.get('/admin/maintenance', follow_redirects=True)
    assert result.status_code == 200
    assert b'Disabled' in result.data  # disable mode for other tests
    """
