import json

from helpers import USER_PERM


def test_admin(client, database):
    '''Test that non-admins are barred from admin pages, and admins can access them.'''
    # Admins should be able to view the page
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e1', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    admin_api = client.post('/api/getkey').data.decode("utf-8")
    result = client.get('/admin/users')
    assert result.status_code == 200
    assert b'Users' in result.data

    result = client.get('/admin/createannouncement')
    assert result.status_code == 200
    assert b'Create Announcement' in result.data

    result = client.get('/contests/create')
    assert result.status_code == 200
    assert b'Create Contest' in result.data

    result = client.get('/problems/create')
    assert result.status_code == 200
    assert b'Create Problem' in result.data

    result = client.get('/problems/draft')
    assert result.status_code == 200
    assert b'Draft' in result.data
    client.get('/logout')

    # Normal users should be redirected to home
    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e2', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    result_user = client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)
    user_api = client.post('/api/getkey').data.decode("utf-8")
    assert b'Welcome' in result_user.data
    result_user = client.get('/admin/users')
    assert result_user.status_code == 302
    client.get('/logout')

    # Not logged in users should be redirected to the login page
    result_nouser = client.get('/admin/users')
    assert result_nouser.status_code == 302
    result_nouser = client.get('/admin/users', follow_redirects=True)
    assert b'Log In' in result_nouser.data

    # Test admin-only API
    with open('metadata/homepage.html', 'w') as file:
        file.write('1\nadmin only')
    result = client.get('/api/homepage')
    assert result.status_code == 401
    result = client.get('/api/homepage?key=00000000-0000-0000-0000-000000000000')
    assert result.status_code == 401
    result = client.get('/api/homepage?key=' + user_api)
    assert result.status_code == 401
    result = client.get('/api/homepage?key=' + admin_api)
    assert result.status_code == 200
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.get('/api/homepage')
    assert result.status_code == 200

    # Admins should be able to ban and unban people
    result = client.post('/admin/ban', follow_redirects=True)
    assert b'user ID' in result.data
    result = client.post('/admin/ban', data={'user_id': 100}, follow_redirects=True)
    assert b'exist' in result.data
    result = client.post('/admin/ban', data={'user_id': 1}, follow_redirects=True)
    assert b'yourself' in result.data
    result = client.post('/admin/ban', data={'user_id': 2}, follow_redirects=True)
    assert result.status_code == 200
    assert b'Successfully banned' in result.data
    result = client.post('/admin/ban', data={'user_id': 2}, follow_redirects=True)
    assert result.status_code == 200
    assert b'Successfully unbanned' in result.data

    # Test password reset feature
    result = client.post('/admin/resetpass', data={'user_id': 2}, follow_redirects=True)
    assert result.status_code == 200
    assert b'was reset' in result.data

    # Test make admin feature
    result = client.post('/admin/updateperms?user_id=2',
                         data={'perms': [USER_PERM["ADMIN"]]},
                         follow_redirects=True)
    assert result.status_code == 200
    assert b"Granted [&#39;ADMIN&#39;]" in result.data

    # Regular admins cannot revoke admin or grant super-admin
    result = client.post('/admin/updateperms?user_id=2', follow_redirects=True)
    assert result.status_code == 200
    assert b"Only the super-admin can revoke admin status" in result.data

    result = client.post('/admin/updateperms?user_id=2',
                         data={'perms': [USER_PERM["ADMIN"], USER_PERM["SUPERADMIN"]]},
                         follow_redirects=True)
    assert result.status_code == 200
    assert b"Only the super-admin can create super-admins" in result.data

    # But superadmins can
    database.execute("INSERT INTO user_perms VALUES(1, ?)", USER_PERM["SUPERADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    result = client.get('/admin/users?q=admin')
    assert result.status_code == 200
    assert b'e1' in result.data
    assert b'normal_user' not in result.data


    result = client.post('/admin/updateperms?user_id=2', follow_redirects=True)
    assert result.status_code == 200
    assert b"Revoked [&#39;ADMIN&#39;]" in result.data

    # Test announcements creation and editing
    result = client.post('/admin/createannouncement', data={
        'name': 'testing',
        'description': 'testing announcement'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully created' in result.data

    result = client.post('/admin/editannouncement/1', data={
        'name': '',
        'description': 'new testing announcement'
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'empty' in result.data

    result = client.post('/admin/editannouncement/1', data={
        'name': 'testing',
        'description': 'new testing announcement'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully edited' in result.data

    result = client.get('/api/announcements?id=1')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['1'] == 'new testing announcement'

    # For some reason Windows locks the announcement file, preventing it from being
    # deleted in the next test
    del result
    import gc
    gc.collect()

    result = client.post('/admin/deleteannouncement',
                         data={'aid': 1}, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully deleted' in result.data
