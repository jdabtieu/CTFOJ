import jwt

from datetime import datetime, timedelta


def test_register(client, database):
    '''Test the registration process for users.'''
    result = client.post('/register', data={
        'username': 'testing',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 200
    assert b'account creation' in result.data

    # Manually generate token to check
    exp = datetime.utcnow() + timedelta(seconds=1800)
    token = jwt.encode(
        {
            'email': 'testingemail@email.com',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )

    result = client.get(f'/confirmregister/{token}', follow_redirects=True)
    assert result.request.path == "/problem/helloworld"

    result = client.get(f'/confirmregister/{token}', follow_redirects=True)
    assert result.status_code == 200
    assert b'invalid' in result.data
    assert result.request.path == "/register"

    # Test invalid requests
    result = client.post('/register', data={
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'Invalid username' in result.data

    result = client.post('/register', data={
        'username': 'testing-()*',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'Invalid username' in result.data

    result = client.post('/register', data={
        'username': 'testing',
        'password': 'e',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'8 characters' in result.data

    result = client.post('/register', data={
        'username': 'testing',
        'password': 'testingpassword',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'do not match' in result.data

    result = client.post('/register', data={
        'username': 'testing',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemai+l@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'character not allowed' in result.data

    result = client.post('/register', data={
        'username': 'testing',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'already exists' in result.data

    result = client.post('/register', data={
        'username': 'randouser',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'already exists' in result.data

    result = client.get('/confirmregister/fake', follow_redirects=True)

    assert b'invalid' in result.data

    # Manually generate token to check
    exp = datetime.utcnow() - timedelta(seconds=1800)
    token = jwt.encode(
        {
            'email': 'testingemail@email.com',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )

    result = client.get(f'/confirmregister/{token}', follow_redirects=True)
    assert b'expired' in result.data

    result = client.post('/register', data={
        'username': 'testing2',
        'password': 'testingpass2',
        'confirmation': 'testingpass2',
        'email': 'testingemail2@email.com'
    }, follow_redirects=True)

    # Manually generate token to check
    exp = datetime.utcnow() + timedelta(seconds=1800)
    token = jwt.encode(
        {
            'email': 'testingemail2@email.com',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )

    result = client.get('/cancelregister/faketoken', follow_redirects=True)
    assert b'invalid' in result.data

    result = client.get(f'/cancelregister/{token}', follow_redirects=True)
    assert b'successfully removed' in result.data

    result = client.get(f'/cancelregister/{token}', follow_redirects=True)
    assert b'invalid' in result.data
