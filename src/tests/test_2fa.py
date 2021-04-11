def test_2fa(client, database):
    '''Test the 2fa mechanism, including toggling it in the settings page.'''
    database.execute("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 1, 0, 1, 0);")

    result = client.get('/confirmlogin/badtoken')
    assert b'Invalid' in result.data

    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/settings/toggle2fa',
                         data={'password': 'CTFOJadmin'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully enabled' in result.data
    client.get('/logout', follow_redirects=True)

    result = client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    assert b'confirmation email' in result.data
