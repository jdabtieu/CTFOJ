import secrets
import sys

try:
    with open('secret_key.txt', 'r') as file:
        secret_key = file.readline().strip()
        SECRET_KEY = secret_key
except Exception as e:
    sys.stderr.write(str(e))
    secret = secrets.token_hex(48)  # 384 bits
    with open('secret_key.txt', 'w+') as file:
        file.write(secret)
        secret_key = file.readline().strip()
        SECRET_KEY = secret_key
SESSION_PERMANENT = False
SESSION_TYPE = "filesystem"
MAIL_SERVER = "smtp.gmail.com"  # configured to work with gmail
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your email address"
MAIL_PASSWORD = "your email password"
MAIL_DEFAULT_SENDER = ("sender name", "sender email")
CLUB_NAME = "your club name"
LOGGING_FILE_LOCATION = 'logs/application.log'
SESSION_COOKIE_SAMESITE = 'Lax'
USE_CAPTCHA = True
HCAPTCHA_SECRET = 0xdeadbeef
HCAPTCHA_SITE = 'site_key'
USE_HOMEPAGE = True
