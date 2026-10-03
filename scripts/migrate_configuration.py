#!/usr/bin/env python3
"""Import pre-portable literal configuration without executing the old source.

Stop both services first; back up the database and .env. Run using the deployment
process environment so overrides are retained. No settings or secrets are printed.
"""
import argparse
import ast
import json
import os
import sqlite3
from contextlib import closing
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from connection_settings import FIELDS, validate


def migrate(source, database):
    constants = {}
    for node in ast.parse(Path(source).read_text()).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                constants[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, TypeError):
                pass
    values = {name: str(constants[name]) for name in FIELDS if name in constants}
    if 'COLLECTIONS' in constants:
        values['KEEP_COLLECTIONS'] = json.dumps(constants['COLLECTIONS'])
    values.setdefault('EMAIL_ENABLED', 'true' if os.environ.get('SMTP_PASSWORD') else 'false')
    values.setdefault('SMTP_SECURITY', 'ssl')
    for name in FIELDS:
        if name in os.environ:
            values[name] = os.environ[name]
    values = {name: validate(name, value) for name, value in values.items() if value and value != 'None'}
    # mode=rw refuses to silently create an empty replacement database.
    with closing(sqlite3.connect(Path(database).resolve().as_uri() + '?mode=rw', uri=True)) as db, db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('CREATE TABLE IF NOT EXISTS connection_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
        db.execute('CREATE TABLE IF NOT EXISTS portable_configuration (version INTEGER NOT NULL)')
        db.execute('INSERT INTO portable_configuration SELECT 1 WHERE NOT EXISTS (SELECT 1 FROM portable_configuration)')
        db.executemany('INSERT OR IGNORE INTO connection_settings VALUES (?, ?)', values.items())
    return len(values)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', required=True)
    parser.add_argument('--database', required=True)
    args = parser.parse_args()
    migrate(args.source, args.database)
    print('Configuration migration complete; existing saved settings and application data were preserved.')
