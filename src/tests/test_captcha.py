from helpers import check_captcha

def test_captcha(client, database):
    result = check_captcha("", "", "")
    assert b'invalid' in result.data

    result = check_captcha("", "fakeresponse", "")
    assert b'invalid' in result.data