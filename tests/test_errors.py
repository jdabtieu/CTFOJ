def test_errors(client):
    '''Tests for some common errors. Because an internal server error should not happen, it is not tested for.'''
    result = client.get("/this_path_better_not_exist")
    assert result.status_code == 404
    assert b'Page Not Found' in result.data
    result = client.post('/login')
    assert result.status_code == 400
    assert b'Log In' in result.data
    result = client.get('/teapot')
    assert result.status_code == 418
    assert b'Teapot' in result.data
