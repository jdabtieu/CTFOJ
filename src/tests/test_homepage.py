import json


def test_homepage(client, database):
    """
    Test that admins can create contests and contest problems,
    and non-admins can access them.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0, '00000000-0000-0000-0000-000000000000', 0, 0, 0)"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    with open('metadata/homepage.html', 'w') as file:
        file.write("1\nThis is the homepage<p>HTML should render too</p>")

    result = client.get('/api/homepage')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['data'] == 'This is the homepage<p>HTML should render too</p>'

    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Announcements' not in result.data

    with open('metadata/homepage.html', 'w') as file:
        file.write("2\nThis is the homepage<p>HTML should render too</p>")

    result = client.get('/api/homepage')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['data'] == 'This is the homepage<p>HTML should render too</p>'

    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Announcements' in result.data

    result = client.get('/admin/edithomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Edit' in result.data

    result = client.post('/admin/edithomepage', follow_redirects=True)
    assert b'required fields' in result.data

    result = client.post('/admin/edithomepage', follow_redirects=True, data={"content": "some content"})
    assert b'successfully' in result.data
