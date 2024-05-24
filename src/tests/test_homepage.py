from helpers import USER_PERM
from application import app  # noqa


def test_homepage(client, database):
    """
    Test that admins can create contests and contest problems,
    and non-admins can access them.
    """

    # First, check that the homepage redirect to login works
    result = client.get('/')
    assert result.status_code == 302

    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    with open('metadata/homepage.html', 'w') as file:
        file.write("1\nThis is the homepage<p>HTML should render too</p>")

    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Announcements' not in result.data
    assert b'This is the homepage' in result.data

    with open('metadata/homepage.html', 'w') as file:
        file.write("2\nThis is the homepage<p>HTML should render too</p>")

    result = client.get('/admin/previewhomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Announcements' in result.data
    assert b'This is the homepage' in result.data

    result = client.get('/admin/edithomepage', follow_redirects=True)
    assert result.status_code == 200
    assert b'Edit' in result.data

    result = client.post('/admin/edithomepage', follow_redirects=True)
    assert b'settings.py' in result.data

    result = client.post('/admin/edithomepage', follow_redirects=True, data={"content": "some content", "method": "2"})
    assert b'successfully' in result.data

    client.get('/logout')

    app.config["USE_HOMEPAGE"] = True
    result = client.get('/')
    assert result.status_code == 200
    assert b"some content" in result.data
    app.config["USE_HOMEPAGE"] = False
