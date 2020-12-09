def test_pages(client, database):
    '''Test if all the pages are accessible.'''
    database.execute("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 0, 1);")

    result = client.post('/login', data = {'username': 'normal_user', 'password': 'CTFOJadmin'}, follow_redirects = True)
    print(result.data)
    assert result.status_code == 200
    assert b'Announcements' in result.data

    result = client.get('/problems')
    assert result.status_code == 200
    assert b'Problems' in result.data

    result = client.get('/contests')
    assert result.status_code == 200
    assert b'Future Contests' in result.data

    result = client.get('/changepassword')
    assert result.status_code == 200
    assert b'Password must be at least 8 characters long.' in result.data

    result = client.get('/logout')
    assert result.status_code == 302
