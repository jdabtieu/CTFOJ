# Installation
Prerequisites: Python 3, SQLite 3

For updating instructions, click [here](#updating).

Although CTFOJ can run on Linux and Windows, it is recommended to run it
on a modern Linux distribution such as Ubuntu 22.04 LTS. This guide assumes that
you are running Linux. If you're running on Windows, your user account must
be able to create symlinks. For instructions on enabling this, visit
[this article](https://portal.perforce.com/s/article/3472)

# Step 0 - Getting a copy of CTFOJ
The best way to get a copy of CTFOJ is to clone the repository at the version
you want. It is recommended to use the latest stable release, whose version
number can be found [here](https://github.com/jdabtieu/CTFOJ/releases). For
example, to get version v2.4.3, run
```bash
$ git clone --depth 1 --branch v2.4.3 https://github.com/jdabtieu/CTFOJ.git
$ cd CTFOJ
```

# Installation Instructions
To install CTFOJ, you must have bash or another shell interpreter installed. For
Windows, this means [Git Bash](https://git-scm.com/downloads) or even better,
use WSL2.

## Step 0
Install Python, pip, virtualenv, nano, sqlite<br>
If you are running Windows, your user account must be able to create symlinks.
For instructions on enabling this, visit
[this article](https://portal.perforce.com/s/article/3472).

## Step 1
Run INSTALL.sh
```bash
$ chmod +x INSTALL.sh
$ ./INSTALL.sh
```

The installer will prompt you three times:
1. For the data directory, this is where persistent files will be stored
(metadata, database, etc.). If you are running Docker, you should point this to
the bind point of a volume. Otherwise, `../data` will suffice.
2. For an admin email. This email will be associated with the admin email.
3. To configure settings. In settings.py, you should add your email credentials
as indicated by default_settings.py. **If you are using Gmail, use an app
password instead of your account password. For more info, see
[here](https://support.google.com/accounts/answer/185833).**
Next, you should choose whether to use a CAPTCHA or not, and add your hCaptcha
site and secret keys if you are using a CAPTCHA. After that, you should add a
custom name for your club and change any other settings that you wish to change.
Finally, you should choose whether to enable a homepage. If you decide to do so,
make sure to specify the location of the homepage.

If everything went well, the installer will now run the app in debug mode. You
can access it at <http://localhost:5000>. Make sure it loads after 10-20 seconds
and then you can kill it with Ctrl+C.

## Step 2 - Logging in for the first time
An admin account has been created in step 1. You can log in to it using the
credentials `admin:CTFOJadmin`. Make sure you change your password immediately
after logging in. Enabling 2FA is also recommended for the admin account. You
can change your password and enable 2FA through the settings page.

Furthermore, when regular users log in for the first time, they will be directed
to a helloworld problem. You should create a helloworld problem as a
welcome/landing page. This problem must have an id of 'helloworld', without the
single quotes. You can do this on the 'Create Problem' page in the admin
toolbar, once logged in. Markdown is supported. See below for an example
helloworld problem:
```
**Welcome to CTF Club!** In each problem, you must find a flag hidden somewhere on the problem page.

The flag for this problem is: `CTF{your_first_ctf_flag}`
```

### Step 3 - Running CTFOJ
To run the application in debug mode, you can use the following command while in
the src directory. This is for development purposes. You should never expose the
app to the web using debug mode. You should run the app through a WSGI
application, such as Gunicorn or uWSGI.
```bash
$ python3 application.py
```

To run though Gunicorn, for example, the following command can be used inside the src directory:
```bash
$ gunicorn --bind 0.0.0.0:80 --log-file gunicorn.log --capture-output -w 4 wsgi:app
```

# Optional Steps
You may optionally replace the default favicon.png file in the static folder
with another icon of your choice (must be named favicon.png). This icon will be
displayed in the title bar of a CTFOJ tab in users' web browsers.

`daily_tasks.py` creates automatic backups of site data and splits logs by
date. To set it up, use your task scheduler to run it once per day/week, 
depending on your preferred backup frequency. For example, for cron, the following
command will run it every day at 8am UTC.
```cron
0 8 * * * cd /path/to/install/CTFOJ/src && python3 daily_tasks.py
```
And this command will run it every Sunday at 8am UTC.
```cron
0 8 * * 0 cd /path/to/install/CTFOJ/src && python3 daily_tasks.py
```
Make sure you replace `/path/to/install` with your CTFOJ installation path.

# Updating
To update, first fetch the latest changes from GitHub. This can be done with:
```bash
$ git pull
```

Then, revert to the version you are looking for. This can be done with:
```bash
$ git reset --hard [version number]
```
The version number should look like v#.#.#. An example is v2.1.0. Assuming all
goes well, you should see a message like
```
HEAD is now at ###### Some message here
```

Finally, you'll want to restart your WSGI application to apply the changes.
The command will vary depending on your WSGI application.
