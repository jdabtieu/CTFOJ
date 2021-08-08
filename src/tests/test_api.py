def test_assets(client, database):
    '''Test to ensure api functions.'''
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0, NULL)"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.get('/api/getkey')
    assert database.execute("SELECT * FROM users")[0]["api"] == result.data.decode('utf-8')  # noqa

    result = client.get('/api')
    assert result.status_code == 308
