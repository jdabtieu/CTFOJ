def test_homepage(client, database):
    """
    Test that admins can create contests and contest problems,
    and non-admins can access them.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0)"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    with open('templates/unauth_index.html', 'w') as file:
        file.write("1\nThis is the homepage<p>HTML should render too</p>")
    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'HTML should render too' in result.data
    assert b'Announcements' not in result.data

    with open('templates/unauth_index.html', 'w') as file:
        file.write("2\nThis is the homepage<p>HTML should render too</p>")
    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'HTML should render too' in result.data
    assert b'Announcements' in result.data