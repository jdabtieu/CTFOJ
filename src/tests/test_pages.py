from helpers import create_jwt


def test_pages(client, database):
    '''Test if all the normal pages are accessible.'''
    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', "
         "'ctf.mgci+debug@email.com', datetime('now'), 0, 1, 0, NULL, 0, 0, 0, 0)"))

    result = client.get('/privacy')
    assert result.status_code == 200
    assert b'Privacy' in result.data

    result = client.get('/terms')
    assert result.status_code == 200
    assert b'Terms' in result.data

    result = client.get('/problems')
    assert result.status_code == 200
    assert b'Problems' in result.data

    result = client.get('/ranking')
    assert result.status_code == 200
    assert b'Practice Leaderboard' in result.data
    assert b'Contest Leaderboard' not in result.data

    result = client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Announcements' in result.data

    result = client.get('/problems')
    assert result.status_code == 200
    assert b'Problems' in result.data

    result = client.get('/contests')
    assert result.status_code == 200
    assert b'Future Contests' in result.data

    result = client.get('/settings/changepassword')
    assert result.status_code == 200
    assert b'Password must be at least 8 characters long.' in result.data

    result = client.post('/settings/changepassword', data={
        'password': '',
        'newPassword': 'CTFOJadmin123',
        'confirmation': 'CTFOJadmin123'
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'Password cannot be blank' in result.data

    result = client.post('/settings/changepassword', data={
        'password': 'CTFOJadmin',
        'newPassword': 'CTFOJad',
        'confirmation': 'CTFOJad'
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'at least 8' in result.data

    result = client.post('/settings/changepassword', data={
        'password': 'CTFOJadmin',
        'newPassword': 'CTFOJadmin',
        'confirmation': 'CTFOJnotadmin'
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'do not match' in result.data

    result = client.post('/settings/changepassword', data={
        'password': 'CTFOJadmin1',
        'newPassword': 'CTFOJadmin',
        'confirmation': 'CTFOJadmin'
    }, follow_redirects=True)
    assert result.status_code == 401
    assert b'Incorrect' in result.data

    result = client.post('/settings/changepassword', data={
        'password': 'CTFOJadmin',
        'newPassword': 'CTFOJadmin123',
        'confirmation': 'CTFOJadmin123'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'change successful' in result.data

    result = client.get('/settings')
    assert result.status_code == 200
    assert b'Settings' in result.data

    result = client.get('/logout')
    assert result.status_code == 302

    result = client.post('/forgotpassword', data={'email': ''}, follow_redirects=True)
    assert b'blank' in result.data

    result = client.post('/forgotpassword', data={'email': 'ctf.mgci+debug@email.com'})
    assert result.status_code == 200

    result = client.get('/resetpassword/invalidtoken', follow_redirects=True)
    assert result.status_code == 200
    assert b'Forgot' in result.data

    token = create_jwt({'user_id': 2}, 'testing_secret_key')
    result = client.get('/resetpassword/' + token, follow_redirects=True)
    assert result.status_code == 200
    assert b'Reset Password' in result.data

    token = create_jwt({'user_id': 2}, 'testing_secret_key')
    result = client.post('/resetpassword/' + token, data={
        'password': 'CTFOJadmin321',
        'confirmation': 'CTFOJadmin123'
    }, follow_redirects=True)
    assert b'do not match' in result.data

    token = create_jwt({'user_id': 2}, 'testing_secret_key')
    result = client.post('/resetpassword/' + token, data={
        'password': 'CTFOJadmin321',
        'confirmation': 'CTFOJadmin321'
    }, follow_redirects=True)
    assert b'Log In' in result.data

    result = client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin321'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Welcome' in result.data

    result = client.get('/users/normal_user/profile')
    assert result.status_code == 200
    assert b'User Info' in result.data
    assert b'0 Points' in result.data

    result = client.get('/ranking')
    assert result.status_code == 200
