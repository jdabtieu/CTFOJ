import json
import os
import shutil

from datetime import datetime
from datetime import timedelta

from helpers import USER_PERM
from application import app  # noqa


def test_contest(client, database):
    """
    Test that admins can create contests and contest problems,
    and non-admins can access them.
    """
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e1', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    admin_api = client.post('/api/getkey').data.decode("utf-8")

    result = client.post('/contests/create', data={
        'contest_id': '',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'contest ID' in result.data

    result = client.post('/contests/create', data={
        'contest_id': 'testingcontest',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() - timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'end before' in result.data

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

    result = client.post('/contests/create', data={
        'contest_id': 'testingcontest',
        'contest_name': 'Testing Contest',
        'start': datetime.strftime(datetime.now(), "%Y-%m-%dT%H:%M:%S.%fZ"),
        'end': datetime.strftime(datetime.now() + timedelta(600), "%Y-%m-%dT%H:%M:%S.%fZ"),  # noqa E501
        'description': 'testing contest description',
        'scoreboard_visible': True
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'already exists' in result.data

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
    assert json.loads(result.data)['data']['testingcontest'] == 'testing contest description'
    assert 'nonexistent' not in json.loads(result.data)

    result = client.get('/contests')
    assert result.status_code == 200

    result = client.get('/contest/noexist/edit', follow_redirects=True)
    assert b'does not exist' in result.data

    result = client.get('/contest/noexist/delete', follow_redirects=True)
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
        'flag_hint': 'ctf{...}',
        'draft': True,
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'helloworldtesting',
        'name': 'hello world',
        'description': 'a short fun problem',
        'hints': 'try looking at the title',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'draft': True,
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    assert result.status_code == 409
    assert b'already exists' in result.data
    os.remove('test_upload.txt')

    result = client.get('/contest/testingcontest/problem/helloworldtesting')
    assert result.status_code == 200
    assert b'Contest Leaderboard' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting/edit', data={
        'name': 'hello world 2',
        'description': 'a short fun problem 2',
        'hints': 'try looking at the title 2',
        'point_value': 2,
        'category': 'web',
        'file': ('fake_empty_file', ''),
        'instanced': True,
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/drafts')
    assert result.status_code == 200
    assert b'Draft' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting/publish',
                         follow_redirects=True)
    assert result.status_code == 200
    assert b'published' in result.data

    result = client.post('/contest/testingcontest/problem/nonexistent/publish',
                         follow_redirects=True)
    assert result.status_code == 404
    assert b'does not exist' in result.data

    # TODO assert that the instanced box shows up

    client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{hello}'
    })

    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 1
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' in result.data

    result = client.get('/contest/testingcontest')
    assert result.status_code == 200
    assert b'0' in result.data  # 0 non-hidden solves

    result = client.post('/contest/testingcontest/scoreboard/unhide', data={
        'user_id': 1
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' not in result.data
    assert b'unhidden' in result.data

    result = client.get('/contest/testingcontest')
    assert result.status_code == 200
    assert b'1' in result.data  # 1 non-hidden solves

    client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 1
    }, follow_redirects=True)

    result = client.post('/contest/testingcontest/notify', data={
        'subject': 'test subject',
        'message': 'test message'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully notified' in result.data
    client.get('/logout')

    result = client.get('/api/contests?id=testingcontest')
    assert result.status_code == 200
    assert json.loads(result.data)['data']['testingcontest'] == 'testing contest description'

    database.execute(
        ("INSERT INTO 'users' VALUES(2, 'normal_user', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e2', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    client.post('/login', data={
        'username': 'normal_user',
        'password': 'CTFOJadmin'
    }, follow_redirects=True)
    user_api = client.post('/api/getkey').data.decode("utf-8")
    result = client.get('/contest/testingcontest/problem/helloworldtesting')
    assert result.status_code == 200

    result = client.get('/api/contests?id=testingcontest')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['testingcontest'] == 'testing contest description'

    result = client.get('/api/contest/problem?cid=testingcontest&pid=helloworldtesting')
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['description'] == 'a short fun problem 2'
    assert json.loads(result.data)['data']['hints'] == 'try looking at the title 2'

    result = client.get('/api/contest/problem?cid=testingcontest&pid=boo')
    assert result.status_code == 404
    assert json.loads(result.data)['status'] == 'fail'

    # Test rate limiting
    app.config["SUBMIT_RATE_LIMIT_MIN"] = 1
    app.config["SUBMIT_RATE_LIMIT_HOUR"] = 2
    result = client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{wrong}'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'incorrect' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{wrong}'
    }, follow_redirects=True)
    assert result.status_code == 400
    assert b'per minute' in result.data

    database.execute(
        "DELETE FROM submissions WHERE contest_id='testingcontest' AND user_id=2")

    result = client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{hello}'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Congratulations' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting', data={
        'flag': 'ctf{wrong}'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'incorrect' in result.data

    app.config["SUBMIT_RATE_LIMIT_MIN"] = 45
    app.config["SUBMIT_RATE_LIMIT_HOUR"] = 700

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'Hidden' not in result.data

    result = client.get('/contest/testingcontest/submissions')
    assert result.status_code == 200
    assert b'ctf{wrong}' in result.data

    client.get('/logout')

    result = client.get('/api/contests?id=testingcontest&key=' + user_api)
    assert json.loads(result.data)['status'] == 'success'
    assert json.loads(result.data)['data']['testingcontest'] == 'testing contest description'

    # Test export function
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})
    result = client.post('/contest/testingcontest/problem/helloworldtesting/export',
                         follow_redirects=True)
    assert result.status_code == 200
    assert b'exported' in result.data

    result = client.post('/contest/testingcontest/problem/helloworldtesting/export',
                         follow_redirects=True)
    assert b'already exists' in result.data

    result = client.post('/contest/testingcontest/problem/nonexistent/export',
                         follow_redirects=True)
    assert result.status_code == 404
    assert b'does not exist' in result.data

    # Test scoreboard API
    result = client.get('/api/contest/scoreboard/testingcontest')
    assert result.status_code == 401

    result = client.get('/api/contest/scoreboard/testingcontest?key=' + admin_api)
    assert result.status_code == 401

    key = database.execute("SELECT scoreboard_key FROM contests WHERE id='testingcontest'")[0]["scoreboard_key"]
    result = client.get('/api/contest/scoreboard/testingcontest?key=' + key)
    assert result.status_code == 200
    assert result.data == b'{"standings": [{"pos": 1, "team": "normal_user", "score": 2}]}'  # noqa

    # Test hiding and banning
    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 20
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'is not present' in result.data

    result = client.post('/contest/testingcontest/scoreboard/unhide', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'is not hidden' in result.data

    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' in result.data

    result = client.post('/contest/testingcontest/scoreboard/ban', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'banned' in result.data
    assert b'Hidden' in result.data

    result = client.post('/contest/testingcontest/scoreboard/unban', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'unbanned' in result.data

    result = client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 2
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Hidden' in result.data

    result = client.post('/contest/testingcontest/scoreboard/unhide', data={
        'user_id': 1
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'unhidden' in result.data
    assert b'Hidden' in result.data

    # Test other admin functions
    
    result = client.get('/contest/testingcontest/submissions', follow_redirects=True)
    assert result.request.path == '/admin/submissions'

    result = client.get('/admin/submissions')
    assert result.status_code == 200
    assert b'testingcontest-helloworldtesting' in result.data

    result = client.get('/admin/submissions', data={
        'username': 'username1',
        'problem_id': 'problem_id',
        'contest_id': 'contest_id',
        'correct': '1'
    })
    assert result.status_code == 200

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
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    os.remove("test_upload.txt")
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/problem/dynscore', data={
        'flag': 'ctf{hello}'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'457' in result.data

    result = client.post('/contest/testingcontest/problem/dynscore/edit', data={
        'name': 'dynscore',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{nobodywillguessme}',
        'file': ('fake_empty_file', ''),
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/problem/dynscore')
    assert b'457' in result.data

    result = client.post('/contest/testingcontest/problem/dynscore/edit', data={
        'name': 'dynscore',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{nobodywillguessmeagain}',
        'rejudge': True,
        'file': ('fake_empty_file', ''),
    })
    assert result.status_code == 302

    result = client.get('/contest/testingcontest/problem/dynscore')
    assert b'500' in result.data

    client.post('/contest/testingcontest/scoreboard/hide', data={
        'user_id': 1
    }, follow_redirects=True)

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
    assert b'user-ban' in result.data

    result = client.get('/contest/testingcontest/problem/dynscore/download', follow_redirects=True)
    assert result.status_code == 200

    client.post('/contest/testingcontest/delete', follow_redirects=True)
    assert result.status_code == 200

    shutil.rmtree('dl')
    os.mkdir('dl')
    shutil.rmtree('metadata/problems/testingcontest-helloworldtesting')


def test_contest_rejudge(client, database):
    """
    Test rejudge behavior because of how complex it is
    """

    # Set up users
    database.execute(
        ("INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000$XoLKRd3I$"
         "2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e1', "
         "datetime('now'), 0, 1, 0, NULL, 0, 0, 0)"))
    database.execute("INSERT INTO user_perms VALUES(1, ?)", USER_PERM["ADMIN"])
    client.post('/login', data={'username': 'admin', 'password': 'CTFOJadmin'})

    # Set up contest
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

    file = open("test_upload.txt", "w")
    file.write('ree')
    file.close()
    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'static',
        'name': 'static',
        'description': 'static',
        'hints': 'static',
        'point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    assert result.status_code == 302

    result = client.post('/contest/testingcontest/addproblem', data={
        'id': 'dynamic',
        'name': 'dynamic',
        'description': 'dynamic',
        'hints': 'dynamic',
        'score_type': 'dynamic',
        'min_point_value': 1,
        'max_point_value': 500,
        'users_point_value': 1,
        'category': 'general',
        'flag': 'ctf{hello}',
        'flag_hint': 'ctf{...}',
        'file': ('test_upload.txt', 'test_upload.txt')
    })
    assert result.status_code == 302
    os.remove('test_upload.txt')

    # WA --> First AC
    result = client.post('/contest/testingcontest/problem/dynamic', data={
        'flag': 'ctf{wrong}'
    }, follow_redirects=True)
    assert result.status_code == 200

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'None' in result.data

    result = client.post('/contest/testingcontest/problem/dynamic/edit', data={
        'name': 'dynamic',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{wrong}',
        'rejudge': True,
        'file': ('fake_empty_file', ''),
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully' in result.data

    result1 = client.get('/contest/testingcontest/scoreboard')
    assert result1.status_code == 200
    assert b'None' not in result1.data

    # First AC --> WA
    result = client.post('/contest/testingcontest/problem/dynamic/edit', data={
        'name': 'dynamic',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{hello}',
        'rejudge': True,
        'file': ('fake_empty_file', ''),
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully' in result.data

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'None' in result.data

    # WA --> AC and AC --> WA
    result = client.post('/contest/testingcontest/problem/static', data={
        'flag': 'ctf{hello}'
    }, follow_redirects=True)
    assert result.status_code == 200

    result2 = client.get('/contest/testingcontest/scoreboard')
    assert result2.status_code == 200
    assert b'None' not in result2.data

    result = client.post('/contest/testingcontest/problem/dynamic/edit', data={
        'name': 'dynamic',
        'description': 'dynamic is fun',
        'category': 'web',
        'flag': 'ctf{wrong}',
        'rejudge': True,
        'file': ('fake_empty_file', ''),
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully' in result.data

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'None' not in result.data
    assert result.data[result.data.index(b'table'):].replace(b'501', b'1') == result2.data[result2.data.index(b'table'):]  # Check points and last AC

    result = client.post('/contest/testingcontest/problem/static/edit', data={
        'name': 'static',
        'description': 'static is fun',
        'category': 'web',
        'point_value': 1,
        'flag': 'ctf{wrong}',
        'rejudge': True,
        'file': ('fake_empty_file', ''),
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'successfully' in result.data

    result = client.get('/contest/testingcontest/scoreboard')
    assert result.status_code == 200
    assert b'None' not in result.data
    assert result.data[result.data.index(b'table'):] == result1.data[result1.data.index(b'table'):]  # Check points and last AC

    client.post('/contest/testingcontest/delete', follow_redirects=True)
    assert result.status_code == 200
