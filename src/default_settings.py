import secrets
import sys

# DO NOT MODIFY THESE SETTINGS! Scroll down to line 24 for settings that you should change
# The secret key is located in secret_key.txt by default
try:
    with open("secret_key.txt", "r") as file:
        secret_key = file.readline().strip()
        SECRET_KEY = secret_key
except Exception as e:
    sys.stderr.write(str(e))
    secret = secrets.token_hex(48)  # 384 bits
    with open("secret_key.txt", "w+") as file:
        file.write(secret)
        secret_key = file.readline().strip()
        SECRET_KEY = secret_key

TEMPLATES_AUTO_RELOAD = True
SESSION_PERMANENT = False
SESSION_TYPE = "filesystem"
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_HTTPONLY = True

# Configure your email settings here
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your email address"
MAIL_PASSWORD = "your email password"
MAIL_DEFAULT_SENDER = ("sender name", "sender email")

# Configure your hcaptcha settings here
USE_CAPTCHA = False
HCAPTCHA_SECRET = 0xdeadbeef
HCAPTCHA_SITE = "site_key"

# Configure other settings here
"""
CLUB_NAME should store the name of your CTF club. It will be displayed in the navbar,
footer, and page title.
"""
CLUB_NAME = "your club name"

"""
LOGGING_FILE_LOCATION should store a path (relative or absolute) to the location of your
site logs. It is recommended to leave it alone, however, if you change it, you should also
change it in daily_tasks.py.
"""
LOGGING_FILE_LOCATION = "logs/application.log"

"""
USE_HOMEPAGE controls whether a homepage is shown to unregistered users. If you would like
to use a homepage, create one first through the admin console, and then turn this on. If
you do not create a homepage first but turn on this setting, the site will break.
"""
USE_HOMEPAGE = False

"""
HOMEPAGE_FILE should store a path to your homepage. Unless you already have a homepage
elsewhere, it is recommended to use the default location.
"""
HOMEPAGE_FILE = "metadata/homepage.html"

"""
SESSION_COOKIE_SECURE controls whether the session cookie (and other cookies) should only
be served over HTTPS. Change it to False if your club does not support HTTPS or unexpected
errors are happening.
"""
SESSION_COOKIE_SECURE = True

"""
DOCS_URL controls the website users are redirected to when they access the route /docs.
By default, this is set to the GitHub wiki documentation for the CTFOJ platform itself.
"""
DOCS_URL = "https://github.com/jdabtieu/CTFOJ/wiki"
