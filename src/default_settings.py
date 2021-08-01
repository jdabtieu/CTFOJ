import secrets
import sys

# The secret key is located in secret_key.txt by default
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

TEMPLATES_AUTO_RELOAD = True
SESSION_PERMANENT = False
SESSION_TYPE = "filesystem"
SESSION_COOKIE_SAMESITE = 'Lax'

# Configure your smtp server here
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your email address"
MAIL_PASSWORD = "your email password"
MAIL_DEFAULT_SENDER = ("sender name", "sender email")

# Configure your hcaptcha settings here
USE_CAPTCHA = False
HCAPTCHA_SECRET = 0xdeadbeef
HCAPTCHA_SITE = 'site_key'

# Configure other settings here
CLUB_NAME = "your club name"
LOGGING_FILE_LOCATION = 'logs/application.log'
USE_HOMEPAGE = False
HOMEPAGE_FILE = "templates/unauth_index.html"