def test_home(client):
    '''Test if there are any homepage internal server errors.'''
    result = client.get('/')
    assert result.status_code != 500
    assert b'Internal Server Error' not in result.data
