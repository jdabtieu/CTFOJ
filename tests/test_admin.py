def test_admin(client, database):
    '''Test that normal users are barred from admin pages, and admins can access them.'''
    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1);")
    client.post('/login', data = {'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.get('/admin/users')
    assert result.status_code == 200
    assert b'Users' in result.data
    client.post('/logout')

    database.execute("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 0, 1);")
    result_user = client.post('/login', data = {'username': 'normal_user', 'password': 'CTFOJadmin'}, follow_redirects = True)
    print(result_user.data)
    assert b'Welcome' in result_user.data
    # normal users are redirected away
    result_user = client.get('/admin/users')
    assert result_user.status_code == 302
