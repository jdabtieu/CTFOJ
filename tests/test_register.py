import jwt

from datetime import datetime, timedelta

def test_register(client, database):
    '''Test the registration process for users.'''
    result = client.post('/register',
                         data={
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
    ).decode('utf-8')

    result = client.get(f'/confirmregister/{token}')
    assert result.status_code == 302
