from datetime import datetime, timedelta

from helpers import USER_PERM


def endpoint_test(client, endpoint, is_admin):
    # Runs the test against /api/instancer/<endpoint>

    result = client.get(f'/api/instancer/{endpoint}?id=nonexistent')
    assert result.status_code == 404
    assert b'Problem not found' in result.data

    result = client.get(f'/api/instancer/{endpoint}?id=nonexistent/bad')
    assert result.status_code == 404
    assert b'Contest not found' in result.data

    result = client.get(f'/api/instancer/{endpoint}?id=testingcontest/bad')
    if is_admin:
        assert result.status_code == 404
        assert b'Problem not found' in result.data
    else:
        assert result.status_code == 403
        assert b'The contest has not started' in result.data

    result = client.get(f'/api/instancer/{endpoint}?id=testingcontest/helloworldtesting')
    if is_admin:
        assert result.status_code == 500
        assert b'Failed to get a valid response' in result.data
    else:
        assert result.status_code == 403
        assert b'The contest has not started' in result.data


def test_instancer(client, database):
    """
    Test that instancer access permissions are set up properly. For obvious
    reasons, cannot test the actual interface or instancer itself.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, '00000000-0000-0000-0000-000000000000', 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, 1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    result = client.post('/contests/create', data={
        'contest_id': 'testingcontest',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now() + timedelta(500), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True,
        'scoreboard_key': '00000000-0000-0000-0000-000000000000'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Testing Contest' in result.data

    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'instanced': True,
        'draft': True,
        'file': ('fake_empty_file', ''),
    })
    assert result.status_code == 302

    endpoint_test(client, 'query', True)
    endpoint_test(client, 'create', True)
    endpoint_test(client, 'destroy', True)


    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 1, 0, '00000000-0000-0000-0000-000000000001', 0, 0, 0)"))
    client.post('/login', data={'username': 'normal_user', 'password': 'CTFOJadmin'})

    endpoint_test(client, 'query', False)
    endpoint_test(client, 'create', False)
    endpoint_test(client, 'destroy', False)

    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/contest/testingcontest/delete', follow_redirects=True)
    assert result.status_code == 200