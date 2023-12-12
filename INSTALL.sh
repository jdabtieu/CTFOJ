#!/bin/bash

# Make sure important tools are installed
echo "Starting precheck..."
PYTH=$(which python3)
PYTHPIP=$(which pip3)
python3 --version
if [[ $? != 0 ]]; then
    python --version
    if [[ $? != 0 ]]; then
        echo "Python 3 not installed. Make sure you have Python 3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    fi
    if [[ $(python --version | grep "Python 3" | wc -c) -eq 0 ]]; then
        echo "Python 3 not installed. Make sure you have Python 3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    else
        pip --version
        if [[ $? != 0 ]]; then
            echo "pip not installed. Make sure you have pip installed and available in PATH."
            echo "**STOPPING**"
            exit 1
        fi
        PYTH=$(which python)
        PYTHPIP=$(which pip)
    fi
else
    pip3 --version
    if [[ $? != 0 ]]; then
        echo "pip3 not installed. Make sure you have pip3 installed and available in PATH."
        echo "**STOPPING**"
        exit 1
    fi
fi

if [[ $(which sqlite3 | wc -c) -eq 0 ]]; then
    echo "sqlite3 not installed. Make sure it is installed and available in PATH."
    echo "**STOPPING**"
    exit 1
fi
if [[ $(which nano | wc -c) -eq 0 ]]; then
    echo "nano not installed. Make sure it is installed and available in PATH."
    echo "**STOPPING**"
    exit 1
fi

# Create virtualenv to isolate dependencies
"$PYTH" -m venv .
if [[ $? != 0 ]]; then
    echo "venv creation failed. Make sure you have Python 3 and the virtualenv package installed."
    echo "**STOPPING**"
    exit 1
fi
echo "Precheck complete!"
. bin/activate || . Scripts/activate
cd src
echo "Installing dependencies..."
pip install wheel
pip install -r requirements.txt
echo "Data directory (if using Docker, enter the directory that the volume is bound to): "
echo "This directory can be absolute or relative to the src directory"
read DATA_DIR
mkdir "$DATA_DIR"
touch "$DATA_DIR/database.db"
ln -s "$DATA_DIR/database.db" database.db
echo "Creating database..."
sqlite3 database.db < schema.sql
sqlite3 database.db << EOF
INSERT INTO 'users' VALUES(1, 'admin', 'pbkdf2:sha256:150000\$XoLKRd3I\$2dbdacb6a37de2168298e419c6c54e768d242aee475aadf1fa9e6c30aa02997f', 'e', datetime('now'), 0, 1, 0, NULL, 0, 0, 0);
INSERT INTO 'user_perms' VALUES(1, 0); -- helpers.py: SUPERADMIN
EOF
mkdir -p "$DATA_DIR/logs" "$DATA_DIR/dl" "$DATA_DIR/backups" "$DATA_DIR/metadata/contests"
mkdir -p "$DATA_DIR/metadata/problems" "$DATA_DIR/metadata/announcements"
echo "Finishing setup..."
ln -s "$DATA_DIR/logs" logs
ln -s "$DATA_DIR/dl" dl
ln -s "$DATA_DIR/metadata" metadata
ln -s "$DATA_DIR/backups" backups
chmod +x daily_tasks.py
python daily_tasks.py
cp default_settings.py "$DATA_DIR/settings.py"
ln -s "$DATA_DIR/settings.py" settings.py
cp templates/default_homepage.html metadata/homepage.html
echo "Configuring settings..."
echo "Admin Email: "
read ADMIN_EMAIL
sqlite3 database.db << EOF
UPDATE 'users' SET email='$ADMIN_EMAIL' WHERE id=1;
EOF
nano settings.py
echo "Success! CTFOJ is now set up."
echo "Running application as debug... You may exit anytime by hitting Ctrl+C"
python application.py
deactivate
