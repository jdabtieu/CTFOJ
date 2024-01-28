import os

# DO NOT MODIFY THESE SETTINGS! Scroll down to line 17 for settings that you should change
# The secret key is located in secret_key.txt by default
with open("secret_key.txt", "r") as file:
    SECRET_KEY = file.readline().strip()
TEMPLATES_AUTO_RELOAD = True
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = 30 * 24 * 60 * 60  # 30d
WTF_CSRF_TIME_LIMIT = PERMANENT_SESSION_LIFETIME
SESSION_TYPE = "filesystem"
SESSION_COOKIE_SAMESITE = "Strict"
SESSION_COOKIE_HTTPONLY = True
SESSION_FILE_DIR = "session"
os.makedirs(SESSION_FILE_DIR, 0o770, True)

# Configure your email settings here
# If using Gmail, you must use an App Password instead of your account password:
# https://support.google.com/accounts/answer/185833
MAIL_SERVER = "smtp.gmail.com"
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = "your email address"
MAIL_PASSWORD = "your email password"
MAIL_DEFAULT_SENDER = ("sender name", "sender email")

# Configure your hCaptcha settings here
USE_CAPTCHA = False
HCAPTCHA_SECRET = "0xdeADbeEf"
HCAPTCHA_SITE = "site_key"

# Configure other settings here
"""
If you are running CTFOJ under a proxy (e.g. PythonAnywhere, Nginx, or Apache), users'
IP addresses should come from the X-Forwarded-For header. This is done automatically on
PythonAnywhere, but with Nginx, you should add this line to your server block:
        proxy_set_header        X-Forwarded-For  $proxy_add_x_forwarded_for;
Apache/other proxies should also set the header to the real user IP.
If you enable this option, you MUST set the X-Forwarded-For header.
"""
USE_X_FORWARDED_FOR = False

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

"""
If you would like to use CTFOJ-managed instances (see CTFOJ-Instancer on GitHub for setup,
add your Bearer token to the INSTANCER_TOKEN variable.
Then, update INSTANCER_HOST with the http(s) hostname of the instancer server
"""
INSTANCER_TOKEN = ""
INSTANCER_HOST = "http://ctfoj.instancer:8080"

"""
Limit the number of submissions that can be made per contest problem per user per minute.
This is used to prevent brute force attacks. Set to 0 to disable.
"""
SUBMIT_RATE_LIMIT_MIN = 45
SUBMIT_RATE_LIMIT_HOUR = 700
