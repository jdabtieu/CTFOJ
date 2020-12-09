def test_assets(client):
    '''Test to ensure assets are visible.'''
    result = client.get('/assets/css/style.css')
    assert result.status_code == 200
    assert b'Page Not Found' not in result.data

    result = client.get('/assets/images/trash.svg')
    assert result.status_code == 200
    assert b'Page Not Found' not in result.data

    result = client.get('/assets/js/dateconvert.js')
    assert result.status_code == 200
    assert b'Page Not Found' not in result.data
