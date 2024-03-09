#!/usr/bin/env bash
# Exit on error
set -o errexit

# Modify this line as needed for your package manager (pip, poetry, etc.)
pip install -r requirements.txt

# Convert static asset files
# npm install && npm run remove-css-comments
python manage.py collectstatic 

# Apply any outstanding database migrations
python manage.py migrate

# Generate schema
python manage.py spectacular --color --file schema.yml