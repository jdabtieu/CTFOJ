from helpers import create_jwt


def test_2fa(client, database):
    '''Test the 2fa mechanism, including toggling it in the settings page.'''
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e@ex.com', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))

    result = client.get('/confirmlogin/badtoken')
    assert b'Invalid' in result.data

    client.post('/login', data={'username': 'user', 'password': 'CTFOJadmin'})
    result = client.post('/settings/toggle2fa',
                         data={'password': 'CTFOJadmin'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully enabled' in result.data

    result = client.post('/settings/toggle2fa', data={'password': 'wrong'})
    assert b'Incorrect' in result.data

    result = client.get('/settings/toggle2fa')

    client.get('/logout', follow_redirects=True)

    result = client.post('/login', data={'username': 'user', 'password': 'CTFOJadmin'})
    assert b'confirmation email' in result.data

    token = create_jwt({'email': "e@ex.com"}, 'testing_secret_key', -1)
    result = client.get('/confirmlogin/' + token)
    assert b'expired' in result.data

    token = create_jwt({'email': "e@ex.com"}, 'testing_secret_key')
    result = client.get('/confirmlogin/' + token, follow_redirects=True)
    assert b'Welcome, user' in result.data

    result = client.post('/settings/toggle2fa',
                         data={'password': 'CTFOJadmin'}, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully disabled' in result.data
