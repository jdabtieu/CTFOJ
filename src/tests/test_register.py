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
    assert b'Resend' in result.data

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
    assert b'already in use' in result.data

    result = client.post('/register', data={
        'username': 'randouser',
        'password': 'testingpass',
        'confirmation': 'testingpass',
        'email': 'testingemail@email.com'
    }, follow_redirects=True)

    assert result.status_code == 400
    assert b'already in use' in result.data

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

    # Test resending registration email
    # Manually generate token to check
    exp = datetime.utcnow() - timedelta(seconds=1800)
    token = jwt.encode(
        {
            'username': 'bob',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )

    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    }, follow_redirects=True)
    assert b'expired' in result.data

    result = client.post('/auth/resend_registration_confirmation', data={
        'token': 'abc'
    }, follow_redirects=True)
    assert b'Invalid' in result.data

    exp = datetime.utcnow() + timedelta(seconds=1800)
    token = jwt.encode(
        {
            'username': 'bob',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )

    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    }, follow_redirects=True)
    assert b'doesn\'t exist' in result.data

    token = jwt.encode(
        {
            'username': 'testing',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )
    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    })
    assert result.data == b'/login'
    assert result.status_code == 302

    result = client.post('/register', data={
        'username': 'unverified',
        'password': 'unverified',
        'confirmation': 'unverified',
        'email': 'unverified@email.com'
    }, follow_redirects=True)
    assert result.status_code == 200
    assert b'Resend' in result.data
    token = jwt.encode(
        {
            'username': 'unverified',
            'expiration': exp.isoformat()
        },
        'testing_secret_key',
        algorithm='HS256'
    )
    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    })
    assert result.data == b'OK'
    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    })
    assert result.data == b'OK'
    result = client.post('/auth/resend_registration_confirmation', data={
        'token': token
    })
    assert b'too many times' in result.data