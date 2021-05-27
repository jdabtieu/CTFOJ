#!/usr/bin/python3

import datetime
import os
import secrets
import shutil
import subprocess
import sys

# Backup database if exists
if os.path.exists('database.db'):
    shutil.copy2('database.db', 'database.db.bak')

# backup metadata if exists
if os.path.exists('metadata'):
    # remove older folder
    if os.path.exists('metadata.bak/'):
        shutil.rmtree('metadata.bak/')
    shutil.copytree('metadata/', 'metadata.bak/')

# backup directory structure
cmd = None
if sys.platform.startswith("win"):
    cmd = "tree /A"
else:
    cmd = "tree"
result = subprocess.check_output(cmd, shell=True).decode()
with open("structure.bak", "w") as file:
    file.write(result)

# Generate new secret key
secret = secrets.token_hex(48)  # 384 bits
with open('secret_key.txt', 'w') as file:
    file.write(secret)

# rotate logs
if os.path.exists('logs/application.log'):
    timestamp = datetime.date.strftime(datetime.datetime.now(), "%d-%m-%Y")
    shutil.copy2("logs/application.log", f"logs/{timestamp}-application.log")
    open("logs/application.log", "w").close()
