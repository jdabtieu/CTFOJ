#!/usr/bin/python3

import datetime
import os
import shutil

# Backup database if exists
if os.path.exists('database.db'):
    shutil.copy2('database.db', 'backups/database.db.bak')

# backup metadata if exists
if os.path.exists('metadata'):
    # remove older folder
    try:
        shutil.rmtree('backups/metadata/')
    except Exception:
        pass
    shutil.copytree('metadata/', 'backups/metadata/')

# rotate logs
if os.path.exists('logs/application.log'):
    timestamp = datetime.date.strftime(datetime.datetime.now(), "%d-%m-%Y")
    shutil.copy2("logs/application.log", f"logs/{timestamp}-application.log")
    open("logs/application.log", "w").close()
