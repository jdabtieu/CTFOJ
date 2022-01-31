import json
import os
import shutil

from datetime import datetime
from datetime import timedelta


def test_contest(client, database):
    """
    Test that admins can create contests and contest problems,
    and non-admins can access them.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 1, 0, 1, 0, '00000000-0000-0000-0000-000000000000')"))
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    result = client.post('/contests/create', data={
        'contest_id': 'testingcontest',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Testing Contest' in result.data

    result = client.post('/contest/testingcontest/edit', data={
        'name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Testing Contest' in result.data

    result = client.get('/api/contests?id=testingcontest,nonexistent')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['testingcontest'] == 'testing contest description'
    assert 'nonexistent' not in json.loads(result.data)

    result = client.get('/contests')
    assert result.status_code == 200

    result = client.get('/contest/noexist/edit', follow_redirects=True)
    assert b'does not exist' in result.data

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'Rank' in result.data

    file = open("test_upload.txt", "w")
    file.write('ree')
    file.close()
    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'draft': True,
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    os.remove('test_upload.txt')
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/problem/helloworldtesting/edit', data={
        'name': 'hello world 2',
        'description': 'a short fun problem 2',
        'hints': 'try looking at the title 2',
        'point_value': 2,
        'category': 'web'
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/drafts')
    assert result.status_code == 200
    assert b'Draft' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting/publish',
                         follow_redirects=True)
    assert result.status_code == 200
    assert b'published' in result.data

    client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{hello}'
    })

    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 1
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' in result.data

    result = client.post('/contest/testingcontest/scoreboard/unhide', data={
        'user_id': 1
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' not in result.data

    client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 1}, follow_redirects=True)

    result = client.post('/contest/testingcontest/notify', data={
        'subject': 'test subject',
        'message': 'test message'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'sucessfully notified' in result.data
    client.get('/logout')

    result = client.get('/api/contests?id=testingcontest')
    assert result.status_code == 401
    assert json.loads(result.data)['status'] == 'fail'

    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', "
         "datetime('now'), 0, 0, 1, 0, '00000000-0000-0000-0000-000000000001')"))
    client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)
    result = client.get('/contest/testingcontest/problem/helloworldtesting')
    assert result.status_code == 200

    result = client.get('/api/contests?id=testingcontest')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['testingcontest'] == 'testing contest description'

    result = client.get('/api/contest/problem?cid=testingcontest&pid=helloworldtesting')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['description'] == 'a short fun problem 2'
    assert json.loads(result.data)['hints'] == 'try looking at the title 2'

    result = client.get('/api/contest/problem?cid=testingcontest&pid=boo')
    assert result.status_code == 404
    assert json.loads(result.data)['status'] == 'fail'

    result = client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{hello}'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Congratulations' in result.data

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'Hidden' not in result.data

    client.get('/logout')

    result = client.get('/api/contests?id=testingcontest&key=00000000-0000-0000-0000-000000000001')  # noqa
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['testingcontest'] == 'testing contest description'

    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/contest/testingcontest/problem/helloworldtesting/export',
                         follow_redirects=True)
    assert result.status_code == 200
    assert b'exported' in result.data

    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' in result.data

    result = client.get('/admin/submissions')
    assert result.status_code == 200
    assert b'testingcontest-helloworldtesting' in result.data

    file = open("test_upload.txt", "w")
    file.write('ree')
    file.close()
    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'dynscore',
        'name': 'dynamic',
        'description': 'dyntest',
        'hints': '',
        'score_type': 'dynamic',
        'min_point_value': 1,
        'max_point_value': 500,
        'users_point_value': 0,
        'category': 'general',
        'flag': 'ctf{hello}',
        'draft': False,
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    os.remove("test_upload.txt")
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/problem/dynscore', data={
        'flag': 'ctf{hello}'
    })
    assert result.status_code == 200

    result = client.get('/contest/testingcontest/problem/dynscore')
    assert b'457' in result.data

    result = client.post('/contest/testingcontest/problem/dynscore/edit', data={
        'name': 'dynscore',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{nobodywillguessme}'
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/problem/dynscore')
    assert b'457' in result.data

    result = client.post('/contest/testingcontest/problem/dynscore/edit', data={
        'name': 'dynscore',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{nobodywillguessmeagain}',
        'rejudge': True
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/problem/dynscore')
    assert b'500' in result.data

    client.get('/logout')

    client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'Hidden' in result.data
    assert b'admin' not in result.data

    client.get('/logout')

    client.post('/login', data={
        'username': 'admin',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)

    result = client.post('/contest/testingcontest/scoreboard/ban', follow_redirects=True, data={'user_id': 2})
    assert result.status_code == 200
    assert b'-999999' in result.data

    result = client.get('/contest/testingcontest/problem/dynscore/download', follow_redirects=True)
    assert result.status_code == 200

    client.post('/contest/testingcontest/delete', follow_redirects=True)
    assert result.status_code == 200

    shutil.rmtree('dl')
    os.mkdir('dl')
    shutil.rmtree('metadata/problems/testingcontest-helloworldtesting')
