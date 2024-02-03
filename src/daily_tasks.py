#!/usr/bin/env python3

import datetime
import os
import shutil

# Back up data
timestamp = datetime.date.strftime(datetime.datetime.now(), "%d-%m-%Y-%H-%M-%S")
os.makedirs(f'backups/{timestamp}', 0o770)
shutil.copy2('database.db', f'backups/{timestamp}/database.db')
shutil.copytree('metadata/', f'backups/{timestamp}/metadata/')

# Rotate logs
if os.path.exists('logs/application.log'):
    timestamp = datetime.date.strftime(datetime.datetime.now(), "%d-%m-%Y")
    shutil.copy2("logs/application.log", f"logs/{timestamp}-application.log")
    open("logs/application.log", "w").close()
